package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	proto "github.com/cooldogedev/spectrum/protocol"
	packet2 "github.com/cooldogedev/spectrum/server/packet"
	"github.com/google/uuid"
	"github.com/klauspost/compress/snappy"
	"github.com/sandertv/gophertunnel/minecraft"
	"github.com/sandertv/gophertunnel/minecraft/protocol"
	"github.com/sandertv/gophertunnel/minecraft/protocol/login"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
)

const (
	flagPacketCompressed = 0x01
	flagPacketNotNeeded  = 0x02

	compressionThreshold = 128
	maxSendBuffer        = 16384
)

type Conn struct {
	log *slog.Logger

	addr *net.UDPAddr
	conn io.ReadWriteCloser

	reader *proto.Reader
	writer *proto.Writer

	clientData   login.ClientData
	identityData login.IdentityData

	runtimeID uint64
	uniqueID  int64

	shieldID int32
	latency  atomic.Int64

	clientPacketLoss atomic.Value

	header *packet.Header
	pool   packet.Pool

	ch      chan struct{}
	flusher chan struct{}
	running sync.WaitGroup

	sendBufferMu sync.Mutex
	flushMu      sync.Mutex
	sendBuffer   []packet.Packet

	chunkRadius int

	initialConnection bool
	connectArgs       []string
	clientProtocol    int

	writeBuffer []byte

	once sync.Once
}

func NewConn(log *slog.Logger, conn io.ReadWriteCloser, authenticator Authenticator, pool packet.Pool, chunkRadius int) (*Conn, error) {
	c := &Conn{
		log: log,

		conn: conn,

		reader: proto.NewReader(conn),
		writer: proto.NewWriter(conn),

		header: &packet.Header{},
		pool:   pool,

		ch:      make(chan struct{}),
		flusher: make(chan struct{}),

		sendBuffer: make([]packet.Packet, 0, 512),

		chunkRadius: chunkRadius,
	}
	c.latency.Store(0)
	c.clientPacketLoss.Store(float64(0))

	connectionRequestPacket, err := c.expect(packet2.IDConnectionRequest)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	c.log.Info("received backend connection request")

	connectionRequest, _ := connectionRequestPacket.(*packet2.ConnectionRequest)

	c.initialConnection, c.connectArgs, c.clientProtocol = connectionRequest.InitialConnection, connectionRequest.Args, int(connectionRequest.ClientProtocol)

	addr, err := net.ResolveUDPAddr("udp", connectionRequest.Addr)
	if err != nil {
		_ = c.Close()
		return nil, err
	}

	c.addr = addr
	if err := json.Unmarshal(connectionRequest.ClientData, &c.clientData); err != nil {
		_ = c.Close()
		return nil, err
	}

	if err := json.Unmarshal(connectionRequest.IdentityData, &c.identityData); err != nil {
		_ = c.Close()
		return nil, err
	}

	c.log = c.log.With("username", c.identityData.DisplayName)

	if authenticator != nil && !authenticator(c.identityData, connectionRequest.Token) {
		_ = c.Close()
		return nil, errors.New("authentication failed")
	}

	c.runtimeID = uint64(crc32.ChecksumIEEE([]byte(c.identityData.XUID)))
	c.uniqueID = int64(c.runtimeID)
	_ = c.WritePacket(&packet2.ConnectionResponse{RuntimeID: c.runtimeID, UniqueID: c.uniqueID})
	if err := c.internalFlush(); err != nil {
		_ = c.Close()
		return nil, err
	}
	c.log.Info("sent backend connection response", "initial_connection", c.initialConnection, "client_protocol", c.clientProtocol)

	return c, nil
}

// Respond ...
func (c *Conn) Respond() {
	c.running.Add(1)
	go c.handleFlusher()
}

// handleFlusher ...
func (c *Conn) handleFlusher() {
	ticker := time.NewTicker(time.Second / 20)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := c.internalFlush(); err != nil {
				c.running.Done()
				_ = c.Close()
				c.log.Error("error flushing packets", "err", err)
				return
			}
		case <-c.flusher:
			if err := c.internalFlush(); err != nil {
				c.running.Done()
				_ = c.Close()
				c.log.Error("error flushing packets", "err", err)
				return
			}
		case <-c.ch:
			c.running.Done()
			return
		}
	}
}

// ReadPacket ...
func (c *Conn) ReadPacket() (packet.Packet, error) {
	return nil, errors.New("please use c.ReadPackets()")
}

// ReadPackets reads multiple packets from the connection and returns them as a slice.
func (c *Conn) ReadPackets() ([]packet.Packet, error) {
	if c == nil {
		return nil, errors.New("conn is nil")
	}
	packets, err := c.read()
	if err != nil {
		if !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "connection reset by peer") {
			c.log.Error("error reading packets", "err", err)
		} else {
			c.log.Debug("ignored error reading packets", "err", err)
		}
		return nil, err
	}

	return packets, nil
}

// WritePacket ...
func (c *Conn) WritePacket(pk packet.Packet) error {
	if c == nil {
		return errors.New("conn is nil")
	}
	c.sendBufferMu.Lock()
	defer c.sendBufferMu.Unlock()
	if len(c.sendBuffer) >= maxSendBuffer {
		if conn := c.conn; conn != nil {
			_ = conn.Close()
		}
		return errors.New("send buffer is full")
	}
	c.sendBuffer = append(c.sendBuffer, pk)
	return nil
}

// ClientProtocol ...
func (c *Conn) ClientProtocol() int {
	return c.clientProtocol
}

// Flush ...
func (c *Conn) Flush() error {
	c.sendBufferMu.Lock()
	defer c.sendBufferMu.Unlock()

	if len(c.sendBuffer) == 0 {
		return nil
	}

	safeSendToChannel(c.flusher, struct{}{})
	return nil
}

// safeSendToChannel ...
func safeSendToChannel[T any](ch chan T, data T) {
	defer func() {
		if r := recover(); r != nil {
			return
		}
	}()
	select {
	case ch <- data:
	default:
	}
}

// internalFlush ...
func (c *Conn) internalFlush() error {
	c.flushMu.Lock()
	defer c.flushMu.Unlock()

	c.sendBufferMu.Lock()
	sendBufferLen := len(c.sendBuffer)
	if sendBufferLen == 0 {
		c.sendBufferMu.Unlock()
		return nil
	}
	sendBuffer := append([]packet.Packet(nil), c.sendBuffer...)
	c.sendBuffer = c.sendBuffer[:0]
	c.sendBufferMu.Unlock()

	buf := BufferPool.Get().(*bytes.Buffer)
	defer func() {
		buf.Reset()
		BufferPool.Put(buf)
	}()

	if err := protocol.WriteVaruint32(buf, uint32(sendBufferLen)); err != nil {
		return err
	}

	buf2 := BufferPool.Get().(*bytes.Buffer)
	defer func() {
		buf2.Reset()
		BufferPool.Put(buf2)
	}()

	for _, pk := range sendBuffer {
		pk = c.translatePacket(pk, true)
		b, err := c.marshalPacket(buf2, pk)
		if err != nil {
			return err
		}
		if err := protocol.WriteVaruint32(buf, uint32(len(b))); err != nil {
			return err
		}
		if _, err := buf.Write(b); err != nil {
			return err
		}
		buf2.Reset()
	}

	payload := buf.Bytes()
	flags := byte(0)
	if len(payload) > compressionThreshold {
		flags |= flagPacketCompressed
		return c.writer.Write([]byte{flags}, snappy.Encode(nil, payload))
	}
	return c.writer.Write([]byte{flags}, payload)
}

func (c *Conn) marshalPacket(buf *bytes.Buffer, pk packet.Packet) ([]byte, error) {
	c.header.PacketID = pk.ID()
	if err := c.header.Write(buf); err != nil {
		return nil, err
	}
	pk.Marshal(protocol.NewWriter(buf, c.shieldID))
	return buf.Bytes(), nil
}

// ClientData ...
func (c *Conn) ClientData() login.ClientData {
	return c.clientData
}

// IdentityData ...
func (c *Conn) IdentityData() login.IdentityData {
	return c.identityData
}

// ChunkRadius ...
func (c *Conn) ChunkRadius() int {
	return c.chunkRadius
}

// ClientCacheEnabled ...
func (c *Conn) ClientCacheEnabled() bool {
	return false
}

// RemoteAddr ...
func (c *Conn) RemoteAddr() net.Addr {
	return c.addr
}

// Latency ...
func (c *Conn) Latency() time.Duration {
	return time.Duration(c.latency.Load())
}

// ClientPacketLossPercentage ...
func (c *Conn) ClientPacketLossPercentage() float64 {
	return c.clientPacketLoss.Load().(float64)
}

// StartGameContext ...
func (c *Conn) StartGameContext(_ context.Context, data minecraft.GameData) (err error) {
	c.log.Info("starting backend start-game sequence", "world", data.WorldName)
	for _, item := range data.Items {
		if item.Name == "minecraft:shield" {
			c.shieldID = int32(item.RuntimeID)
			break
		}
	}

	startGame := &packet.StartGame{
		Difficulty:                   data.Difficulty,
		EntityUniqueID:               c.uniqueID,
		EntityRuntimeID:              c.runtimeID,
		PlayerGameMode:               data.PlayerGameMode,
		PlayerPosition:               data.PlayerPosition,
		Pitch:                        data.Pitch,
		Yaw:                          data.Yaw,
		WorldSeed:                    data.WorldSeed,
		Dimension:                    data.Dimension,
		WorldSpawn:                   data.WorldSpawn,
		EditorWorldType:              data.EditorWorldType,
		CreatedInEditor:              data.CreatedInEditor,
		ExportedFromEditor:           data.ExportedFromEditor,
		PersonaDisabled:              data.PersonaDisabled,
		CustomSkinsDisabled:          data.CustomSkinsDisabled,
		GameRules:                    data.GameRules,
		Time:                         data.Time,
		Blocks:                       data.CustomBlocks,
		AchievementsDisabled:         true,
		Generator:                    1,
		EducationFeaturesEnabled:     true,
		MultiPlayerGame:              true,
		MultiPlayerCorrelationID:     uuid.Must(uuid.NewRandom()).String(),
		CommandsEnabled:              true,
		WorldName:                    data.WorldName,
		LANBroadcastEnabled:          true,
		PlayerMovementSettings:       data.PlayerMovementSettings,
		WorldGameMode:                data.WorldGameMode,
		ServerAuthoritativeInventory: data.ServerAuthoritativeInventory,
		PlayerPermissions:            data.PlayerPermissions,
		Experiments:                  data.Experiments,
		ClientSideGeneration:         data.ClientSideGeneration,
		ChatRestrictionLevel:         data.ChatRestrictionLevel,
		DisablePlayerInteractions:    data.DisablePlayerInteractions,
		BaseGameVersion:              data.BaseGameVersion,
		GameVersion:                  protocol.CurrentVersion,
		UseBlockNetworkIDHashes:      data.UseBlockNetworkIDHashes,
	}
	if err = c.WritePacket(startGame); err != nil {
		return err
	}
	c.log.Info("queued start game packet")

	if err = c.WritePacket(&packet.ItemRegistry{Items: data.Items}); err != nil {
		return err
	}
	c.log.Info("queued item registry packet")

	if _, err = c.expect(packet.IDRequestChunkRadius); err != nil {
		return err
	}
	c.log.Info("received request chunk radius")

	if err := c.WritePacket(&packet.ChunkRadiusUpdated{ChunkRadius: int32(c.ChunkRadius())}); err != nil {
		return err
	}
	c.log.Info("queued chunk radius updated", "chunk_radius", c.ChunkRadius())

	if err := c.WritePacket(&packet.PlayStatus{Status: packet.PlayStatusLoginSuccess}); err != nil {
		return err
	}
	c.log.Info("queued play status login success")

	if _, err = c.expect(packet.IDSetLocalPlayerAsInitialised); err != nil {
		return err
	}
	c.log.Info("received set local player as initialised")
	return
}

// InitialConnection ...
func (c *Conn) InitialConnection() bool {
	return c.initialConnection
}

// ConnectArgs ...
func (c *Conn) ConnectArgs() []string {
	return c.connectArgs
}

// Close ...
func (c *Conn) Close() error {
	if c == nil {
		return errors.New("conn is nil")
	}
	c.once.Do(func() {
		close(c.ch)

		c.sendBufferMu.Lock()
		for i := range c.sendBuffer {
			c.sendBuffer[i] = nil
		}
		c.sendBuffer = nil
		c.sendBufferMu.Unlock()

		go func() {
			c.running.Wait()
			close(c.flusher)

			_ = c.conn.Close()
		}()
	})
	return nil
}

// read reads packets from the reader and returns it.
func (c *Conn) read() (packets []packet.Packet, err error) {
	select {
	case <-c.ch:
		return nil, errors.New("connection closed")
	default:
		payload, err := c.reader.ReadPacket()
		if err != nil {
			return nil, err
		}

		flags := payload[0]

		var buf *bytes.Buffer

		if flags&flagPacketCompressed != 0 {
			decompressed, err := snappy.Decode(nil, payload[1:])
			if err != nil {
				return nil, err
			}
			buf = bytes.NewBuffer(decompressed)
		} else {
			buf = bytes.NewBuffer(payload[1:])
		}

		header := &packet.Header{}
		var packetLen uint32
		if err := protocol.Varuint32(buf, &packetLen); err != nil {
			return nil, fmt.Errorf("read packet length: %w", err)
		}

		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic while reading packet %v: %v", header.PacketID, r)
			}
		}()

		packets = make([]packet.Packet, 0, packetLen)

		for i := uint32(0); i < packetLen; i++ {
			var bufLen uint32
			if err := protocol.Varuint32(buf, &bufLen); err != nil {
				return nil, fmt.Errorf("read packet buffer length: %w", err)
			}
			buf2 := bytes.NewBuffer(buf.Next(int(bufLen)))
			if err := header.Read(buf2); err != nil {
				return nil, fmt.Errorf("read packet header: %w", err)
			}
			factory, ok := c.pool[header.PacketID]
			if !ok {
				return nil, fmt.Errorf("unknown packet ID %v", header.PacketID)
			}
			pk := factory()
			reader := protocol.NewReader(buf2, c.shieldID, false)
			pk.Marshal(reader)
			if latencyPacket, ok := pk.(*packet2.Latency); ok {
				c.latency.Store((time.Now().UnixMilli() - latencyPacket.Timestamp) + latencyPacket.Latency)
				c.clientPacketLoss.Store(float64(latencyPacket.ClientPacketLoss))
				_ = c.WritePacket(&packet2.Latency{Timestamp: 0, Latency: c.latency.Load()})
				continue
			}
			packets = append(packets, c.translatePacket(pk, false))
		}

		return packets, nil
	}
}

// expect reads a packet from the connection and expects it to have the ID passed.
func (c *Conn) expect(id uint32) (packet.Packet, error) {
	packets, err := c.ReadPackets()
	if err != nil {
		return nil, err
	}

	for _, pk := range packets {
		if pk.ID() == id {
			return pk, nil
		}
	}

	return c.expect(id)
}

// translatePacket processes and translates entity identifiers in the given packet.
// It converts runtime and unique IDs between client and server representations depending
// on the direction of the packet.
func (c *Conn) translatePacket(pk packet.Packet, serverSent bool) packet.Packet {
	switch pk := pk.(type) {
	case *packet.ActorEvent:
		pk.EntityRuntimeID = c.translateRuntimeID(pk.EntityRuntimeID, serverSent)
	case *packet.ActorPickRequest:
		pk.EntityUniqueID = c.translateUniqueID(pk.EntityUniqueID, serverSent)
	case *packet.AddActor:
		pk.EntityUniqueID = c.translateUniqueID(pk.EntityUniqueID, serverSent)
		pk.EntityRuntimeID = c.translateRuntimeID(pk.EntityRuntimeID, serverSent)
		pk.EntityMetadata = c.translateMetadata(pk.EntityMetadata, serverSent)
		for i := range pk.EntityLinks {
			pk.EntityLinks[i] = c.translateLink(pk.EntityLinks[i], serverSent)
		}
	case *packet.AddItemActor:
		pk.EntityUniqueID = c.translateUniqueID(pk.EntityUniqueID, serverSent)
		pk.EntityRuntimeID = c.translateRuntimeID(pk.EntityRuntimeID, serverSent)
		pk.EntityMetadata = c.translateMetadata(pk.EntityMetadata, serverSent)
	case *packet.AddPainting:
		pk.EntityUniqueID = c.translateUniqueID(pk.EntityUniqueID, serverSent)
		pk.EntityRuntimeID = c.translateRuntimeID(pk.EntityRuntimeID, serverSent)
	case *packet.AddPlayer:
		pk.AbilityData.EntityUniqueID = c.translateUniqueID(pk.AbilityData.EntityUniqueID, serverSent)
		pk.EntityRuntimeID = c.translateRuntimeID(pk.EntityRuntimeID, serverSent)
		pk.EntityMetadata = c.translateMetadata(pk.EntityMetadata, serverSent)
		for i := range pk.EntityLinks {
			pk.EntityLinks[i] = c.translateLink(pk.EntityLinks[i], serverSent)
		}
		pk.AbilityData.EntityUniqueID = c.translateUniqueID(pk.AbilityData.EntityUniqueID, serverSent)
	case *packet.AddVolumeEntity:
		pk.EntityRuntimeID = uint32(c.translateRuntimeID(uint64(pk.EntityRuntimeID), serverSent))
	case *packet.AdventureSettings:
		pk.PlayerUniqueID = c.translateUniqueID(pk.PlayerUniqueID, serverSent)
	case *packet.AgentAnimation:
		pk.EntityRuntimeID = c.translateRuntimeID(pk.EntityRuntimeID, serverSent)
	case *packet.Animate:
		pk.EntityRuntimeID = c.translateRuntimeID(pk.EntityRuntimeID, serverSent)
	case *packet.AnimateEntity:
		for i := range pk.EntityRuntimeIDs {
			pk.EntityRuntimeIDs[i] = c.translateRuntimeID(pk.EntityRuntimeIDs[i], serverSent)
		}
	case *packet.BossEvent:
		pk.BossEntityUniqueID = c.translateUniqueID(pk.BossEntityUniqueID, serverSent)
		pk.PlayerUniqueID = c.translateUniqueID(pk.PlayerUniqueID, serverSent)
	case *packet.Camera:
		pk.CameraEntityUniqueID = c.translateUniqueID(pk.CameraEntityUniqueID, serverSent)
		pk.TargetPlayerUniqueID = c.translateUniqueID(pk.TargetPlayerUniqueID, serverSent)
	case *packet.ChangeMobProperty:
		pk.EntityUniqueID = int64(c.translateRuntimeID(uint64(pk.EntityUniqueID), serverSent))
	case *packet.ClientBoundMapItemData:
		for i, x := range pk.TrackedObjects {
			if x.Type == protocol.MapObjectTypeEntity {
				x.EntityUniqueID = c.translateUniqueID(x.EntityUniqueID, serverSent)
				pk.TrackedObjects[i] = x
			}
		}
	case *packet.CommandBlockUpdate:
		if !pk.Block {
			pk.MinecartEntityRuntimeID = c.translateRuntimeID(pk.MinecartEntityRuntimeID, serverSent)
		}
	case *packet.CommandOutput:
		pk.CommandOrigin.PlayerUniqueID = c.translateUniqueID(pk.CommandOrigin.PlayerUniqueID, serverSent)
	case *packet.CommandRequest:
		pk.CommandOrigin.PlayerUniqueID = c.translateUniqueID(pk.CommandOrigin.PlayerUniqueID, serverSent)
	case *packet.ContainerOpen:
		pk.ContainerEntityUniqueID = c.translateUniqueID(pk.ContainerEntityUniqueID, serverSent)
	case *packet.CreatePhoto:
		pk.EntityUniqueID = c.translateUniqueID(pk.EntityUniqueID, serverSent)
	case *packet.DebugInfo:
		pk.PlayerUniqueID = c.translateUniqueID(pk.PlayerUniqueID, serverSent)
	case *packet.Emote:
		pk.EntityRuntimeID = c.translateRuntimeID(pk.EntityRuntimeID, serverSent)
	case *packet.EmoteList:
		pk.PlayerRuntimeID = c.translateRuntimeID(pk.PlayerRuntimeID, serverSent)
	case *packet.Event:
		pk.EntityRuntimeID = int64(c.translateRuntimeID(uint64(pk.EntityRuntimeID), serverSent))
		switch data := pk.Event.(type) {
		case *protocol.MobKilledEvent:
			data.KillerEntityUniqueID = c.translateUniqueID(data.KillerEntityUniqueID, serverSent)
			data.VictimEntityUniqueID = c.translateUniqueID(data.VictimEntityUniqueID, serverSent)
		case *protocol.BossKilledEvent:
			data.BossEntityUniqueID = c.translateUniqueID(data.BossEntityUniqueID, serverSent)
		}
	case *packet.Interact:
		pk.TargetEntityRuntimeID = c.translateRuntimeID(pk.TargetEntityRuntimeID, serverSent)
	case *packet.InventoryTransaction:
		switch data := pk.TransactionData.(type) {
		case *protocol.UseItemOnEntityTransactionData:
			data.TargetEntityRuntimeID = c.translateRuntimeID(data.TargetEntityRuntimeID, serverSent)
		}
	case *packet.MobArmourEquipment:
		pk.EntityRuntimeID = c.translateRuntimeID(pk.EntityRuntimeID, serverSent)
	case *packet.MobEffect:
		pk.EntityRuntimeID = c.translateRuntimeID(pk.EntityRuntimeID, serverSent)
	case *packet.MobEquipment:
		pk.EntityRuntimeID = c.translateRuntimeID(pk.EntityRuntimeID, serverSent)
	case *packet.MotionPredictionHints:
		pk.EntityRuntimeID = c.translateRuntimeID(pk.EntityRuntimeID, serverSent)
	case *packet.MoveActorAbsolute:
		pk.EntityRuntimeID = c.translateRuntimeID(pk.EntityRuntimeID, serverSent)
	case *packet.MoveActorDelta:
		pk.EntityRuntimeID = c.translateRuntimeID(pk.EntityRuntimeID, serverSent)
	case *packet.MovePlayer:
		pk.EntityRuntimeID = c.translateRuntimeID(pk.EntityRuntimeID, serverSent)
		pk.RiddenEntityRuntimeID = c.translateRuntimeID(pk.RiddenEntityRuntimeID, serverSent)
	case *packet.NPCDialogue:
		pk.EntityUniqueID = uint64(c.translateUniqueID(int64(pk.EntityUniqueID), serverSent))
	case *packet.NPCRequest:
		pk.EntityRuntimeID = c.translateRuntimeID(pk.EntityRuntimeID, serverSent)
	case *packet.PhotoTransfer:
		pk.OwnerEntityUniqueID = c.translateUniqueID(pk.OwnerEntityUniqueID, serverSent)
	case *packet.PlayerAction:
		pk.EntityRuntimeID = c.translateRuntimeID(pk.EntityRuntimeID, serverSent)
	case *packet.PlayerAuthInput:
		if pk.InputData.Load(packet.InputFlagClientPredictedVehicle) {
			pk.ClientPredictedVehicle = c.translateUniqueID(pk.ClientPredictedVehicle, serverSent)
		}
	case *packet.PlayerList:
		for i := range pk.Entries {
			pk.Entries[i].EntityUniqueID = c.translateUniqueID(pk.Entries[i].EntityUniqueID, serverSent)
		}
	case *packet.RemoveActor:
		pk.EntityUniqueID = c.translateUniqueID(pk.EntityUniqueID, serverSent)
	case *packet.RemoveVolumeEntity:
		pk.EntityRuntimeID = uint32(c.translateRuntimeID(uint64(pk.EntityRuntimeID), serverSent))
	case *packet.Respawn:
		pk.EntityRuntimeID = c.translateRuntimeID(pk.EntityRuntimeID, serverSent)
	case *packet.SetActorData:
		pk.EntityRuntimeID = c.translateRuntimeID(pk.EntityRuntimeID, serverSent)
		pk.EntityMetadata = c.translateMetadata(pk.EntityMetadata, serverSent)
	case *packet.SetActorLink:
		pk.EntityLink = c.translateLink(pk.EntityLink, serverSent)
	case *packet.SetActorMotion:
		pk.EntityRuntimeID = c.translateRuntimeID(pk.EntityRuntimeID, serverSent)
	case *packet.SetLocalPlayerAsInitialised:
		pk.EntityRuntimeID = c.translateRuntimeID(pk.EntityRuntimeID, serverSent)
	case *packet.SetScore:
		for i := range pk.Entries {
			if pk.Entries[i].IdentityType != protocol.ScoreboardIdentityFakePlayer {
				pk.Entries[i].EntityUniqueID = c.translateUniqueID(pk.Entries[i].EntityUniqueID, serverSent)
			}
		}
	case *packet.SetScoreboardIdentity:
		if pk.ActionType != packet.ScoreboardIdentityActionClear {
			for i := range pk.Entries {
				pk.Entries[i].EntityUniqueID = c.translateUniqueID(pk.Entries[i].EntityUniqueID, serverSent)
			}
		}
	case *packet.ShowCredits:
		pk.PlayerRuntimeID = c.translateRuntimeID(pk.PlayerRuntimeID, serverSent)
	case *packet.SpawnParticleEffect:
		pk.EntityUniqueID = c.translateUniqueID(pk.EntityUniqueID, serverSent)
	case *packet.StartGame:
		pk.EntityUniqueID = c.translateUniqueID(pk.EntityUniqueID, serverSent)
		pk.EntityRuntimeID = c.translateRuntimeID(pk.EntityRuntimeID, serverSent)
	case *packet.StructureBlockUpdate:
		pk.Settings.LastEditingPlayerUniqueID = c.translateUniqueID(pk.Settings.LastEditingPlayerUniqueID, serverSent)
	case *packet.StructureTemplateDataRequest:
		pk.Settings.LastEditingPlayerUniqueID = c.translateUniqueID(pk.Settings.LastEditingPlayerUniqueID, serverSent)
	case *packet.TakeItemActor:
		pk.ItemEntityRuntimeID = c.translateRuntimeID(pk.ItemEntityRuntimeID, serverSent)
		pk.TakerEntityRuntimeID = c.translateRuntimeID(pk.TakerEntityRuntimeID, serverSent)
	case *packet.UpdateAbilities:
		pk.AbilityData.EntityUniqueID = c.translateUniqueID(pk.AbilityData.EntityUniqueID, serverSent)
	case *packet.UpdateAttributes:
		pk.EntityRuntimeID = c.translateRuntimeID(pk.EntityRuntimeID, serverSent)
	case *packet.UpdateBlockSynced:
		pk.EntityUniqueID = uint64(c.translateUniqueID(int64(pk.EntityUniqueID), serverSent))
	case *packet.UpdateEquip:
		pk.EntityUniqueID = c.translateUniqueID(pk.EntityUniqueID, serverSent)
	case *packet.UpdatePlayerGameType:
		pk.PlayerUniqueID = c.translateUniqueID(pk.PlayerUniqueID, serverSent)
	case *packet.UpdateSubChunkBlocks:
		for i, entry := range pk.Blocks {
			pk.Blocks[i].SyncedUpdateEntityUniqueID = uint64(c.translateUniqueID(int64(entry.SyncedUpdateEntityUniqueID), serverSent))
		}
		for i, entry := range pk.Extra {
			pk.Extra[i].SyncedUpdateEntityUniqueID = uint64(c.translateUniqueID(int64(entry.SyncedUpdateEntityUniqueID), serverSent))
		}
	case *packet.UpdateTrade:
		pk.VillagerUniqueID = c.translateUniqueID(pk.VillagerUniqueID, serverSent)
		pk.EntityUniqueID = c.translateUniqueID(pk.EntityUniqueID, serverSent)
	}
	return pk
}

// translateRuntimeID converts a runtime ID based on whether the packet was sent by the server or by the client.
// It converts the client-side runtime ID to the server-side runtime ID and vice versa based on the packet direction.
func (c *Conn) translateRuntimeID(runtimeId uint64, serverSent bool) uint64 {
	search := c.runtimeID
	replace := uint64(1)
	if serverSent {
		search = uint64(1)
		replace = c.runtimeID
	}

	if runtimeId == search {
		return replace
	}
	return runtimeId
}

// translateUniqueID converts a unique ID based on whether the packet was sent by the server or by the client.
// It converts the client-side unique ID to the server-side unique ID and vice versa based on the packet direction.
func (c *Conn) translateUniqueID(runtimeId int64, serverSent bool) int64 {
	search := c.uniqueID
	replace := int64(1)
	if serverSent {
		search = int64(1)
		replace = c.uniqueID
	}

	if runtimeId == search {
		return replace
	}
	return runtimeId
}

// translateMetadata updates entity metadata fields that contain unique IDs or runtime IDs,
// translating them based the packet direction.
func (c *Conn) translateMetadata(metadata map[uint32]any, serverSent bool) map[uint32]any {
	for key, value := range metadata {
		switch key {
		case protocol.EntityDataKeyOwner:
			metadata[protocol.EntityDataKeyOwner] = c.translateUniqueID(value.(int64), serverSent)
		case protocol.EntityDataKeyTarget:
			metadata[key] = c.translateUniqueID(value.(int64), serverSent)
		case protocol.EntityDataKeyDisplayOffset:
			metadata[key] = c.translateUniqueID(value.(int64), serverSent)
		case protocol.EntityDataKeyLeashHolder:
			metadata[key] = c.translateUniqueID(value.(int64), serverSent)
		case protocol.EntityDataKeyAgent:
			metadata[key] = c.translateUniqueID(value.(int64), serverSent)
		case protocol.EntityDataKeyBaseRuntimeID:
			metadata[key] = c.translateRuntimeID(value.(uint64), serverSent)
		default:
		}
	}
	return metadata
}

// translateLink updates an entity link by translating the unique IDs of the rider and the ridden entities,
// based on the packet direction.
func (c *Conn) translateLink(link protocol.EntityLink, serverSent bool) protocol.EntityLink {
	link.RiderEntityUniqueID = c.translateUniqueID(link.RiderEntityUniqueID, serverSent)
	link.RiddenEntityUniqueID = c.translateUniqueID(link.RiddenEntityUniqueID, serverSent)
	return link
}
