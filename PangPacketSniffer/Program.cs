using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using PacketDotNet;
using PangCrypt;
using SharpPcap;

namespace PangPacketSniffer
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            var devices = CaptureDeviceList.Instance;
            if (devices.Count < 1)
            {
                Console.WriteLine("No device found on this machine");
                return;
            }

            Console.WriteLine("The following devices are available on this machine:");
            Console.WriteLine("----------------------------------------------------");
            Console.WriteLine();

            var i = 0;

            foreach (var dev in devices)
            {
                Console.WriteLine("{0}) {1} {2}", i, dev.Name, dev.Description);
                i++;
            }

            Console.WriteLine();
            Console.Write("-- Please choose a device to capture: ");
            i = int.Parse(Console.ReadLine());

            var device = devices[i];

            device.OnPacketArrival +=
                device_OnPacketArrival;

            var readTimeoutMilliseconds = 1000;
            device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

            var filter = "ip and tcp";
            device.Filter = filter;

            Console.WriteLine();
            Console.WriteLine("-- The following tcpdump filter will be applied: \"{0}\"", filter);

            if (LoginServerIP == null)
            {
                Console.Write("-- Please input target LoginServer IP: ");
                LoginServerIP = IPAddress.Parse(Console.ReadLine());
                Console.WriteLine();
            }

            if (LoginServerPort == 0)
            {
                Console.Write("-- Please input target LoginServer Port: ");
                LoginServerPort = int.Parse(Console.ReadLine());
                Console.WriteLine();
            }

            BreakIpAddresses.Add(LoginServerIP);
            ServerPorts.Add(LoginServerPort);

            Console.WriteLine
            ("-- Listening on {0}, hit 'Ctrl-C' to exit...",
                device.Description);

            device.Capture();
            device.Close();
        }

        private static void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            var time = e.Packet.Timeval.Date;
            var len = e.Packet.Data.Length;

            var packet = Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);

            var tcpPacket = packet.Extract<TcpPacket>();
            if (tcpPacket != null)
                HandleTcpPacket(tcpPacket);
        }

        private static void HandleTcpPacket(TcpPacket tcpPacket)
        {
            var ipPacket = (IPPacket) tcpPacket.ParentPacket;
            var srcIp = ipPacket.SourceAddress;
            var dstIp = ipPacket.DestinationAddress;
            int srcPort = tcpPacket.SourcePort;
            int dstPort = tcpPacket.DestinationPort;
            if (!BreakIpAddresses.Contains(srcIp) && !BreakIpAddresses.Contains(dstIp))
                return;
            if (!tcpPacket.PayloadData.Any() || tcpPacket.PayloadData.Length < 2)
                return;
            if (tcpPacket.SequenceNumber.Equals(BeforePacket?.SequenceNumber)) // なんか二回来るので
                return;
            BeforePacket = tcpPacket;

            var fromServer = ServerPorts.Contains(srcPort);
            var server = ServerTypeEnum.Unknown;
            var key = LoginKeyIndex;
            var checkHeader = tcpPacket.PayloadData.Take(6).ToArray();
            if (srcIp.Equals(LoginServerIP) || dstIp.Equals(LoginServerIP))
            {
                if (fromServer && srcPort != LoginServerPort || !fromServer && dstPort != LoginServerPort)
                    return;
                var loginHelloHeader = new byte[] {0x00, 0x0b, 0x00, 0x00, 0x00, 0x00};
                server = ServerTypeEnum.Login;
                if (checkHeader.SequenceEqual(loginHelloHeader))
                {
                    Console.WriteLine($"---{server} Server Packet(from:{srcIp})---");
                    Console.WriteLine($"---Hello Message(Size:{tcpPacket.PayloadData.Length})---");
                    Console.WriteLine(tcpPacket.PayloadData.HexDump());
                    LoginKeyIndex = tcpPacket.PayloadData[6];
                    return;
                }

                if (!GotLoginKey)
                {
                    Console.WriteLine("???LoginKey Unknown Skipped???");
                    return;
                }
            }
            else if (fromServer && GameServers.Select(g => (g.IP, g.Port)).Contains((srcIp, srcPort)) ||
                     !fromServer && GameServers.Select(g => (g.IP, g.Port)).Contains((dstIp, dstPort)))
            {
                var gameHelloHeader = new byte[] {0x00, 0x3F, 0x00, 0x01, 0x01};
                server = ServerTypeEnum.Game;
                if (tcpPacket.PayloadData[0] == 0x00 && tcpPacket.PayloadData.Skip(3).Take(5).ToArray().SequenceEqual(gameHelloHeader))
                {
                    Console.WriteLine($"---{server} Server Packet(from:{srcIp})---");
                    Console.WriteLine($"---Hello Message(Size:{tcpPacket.PayloadData.Length})---");
                    HandleMessage(new PangServerMessage(tcpPacket.PayloadData, server));
                    GameKeyIndex = tcpPacket.PayloadData[8];
                    ConnectingGameServer = GameServers.Single(g => Equals(g.IP, srcIp) && g.Port == srcPort);
                    return;
                }
                if (fromServer && !CheckCapture(ConnectingGameServer, srcIp, srcPort) ||
                    !fromServer && !CheckCapture(ConnectingGameServer, dstIp, dstPort))
                    return;
                key = GameKeyIndex;
                if (!GotGameKey)
                {
                    Console.WriteLine("???GameKey Unknown Skipped???");
                    return;
                }
            }
            else if (fromServer && MessageServers.Select(m => (m.IP, m.Port)).Contains((srcIp, srcPort)) ||
                     !fromServer && MessageServers.Select(m => (m.IP, m.Port)).Contains((dstIp, dstPort)))
            {
                var messageHelloHeader = new byte[] {0x00, 0x09, 0x00, 0x00, 0x2E, 0x00};
                server = ServerTypeEnum.Message;
                if (checkHeader.SequenceEqual(messageHelloHeader))
                {
                    Console.WriteLine($"---{server} Server Packet(from:{srcIp})---");
                    Console.WriteLine($"---Hello Message(Size:{tcpPacket.PayloadData.Length})---");
                    HandleMessage(new PangServerMessage(tcpPacket.PayloadData, server));
                    MessageKeyIndex = tcpPacket.PayloadData[7];
                    ConnectingMessageServer = MessageServers.Single(m => Equals(m.IP, srcIp) && m.Port == srcPort);
                    return;
                }

                if (tcpPacket.PayloadData.First() == 0)
                {
                    Console.WriteLine("###Message Hello?###");
                    Console.WriteLine(tcpPacket.PayloadData.HexDump());
                }

                if (fromServer && !CheckCapture(ConnectingMessageServer, srcIp, srcPort) ||
                    !fromServer && !CheckCapture(ConnectingMessageServer, dstIp, dstPort))
                    return;
                server = ServerTypeEnum.Message;
                key = MessageKeyIndex;
                if (!GotMessageKey)
                {
                    Console.WriteLine("???MessageKey Unknown Skipped???");
                    return;
                }
            }
            else
            {
                Console.WriteLine("???Unknown Server Packet Skipped???");
                return;
            }

            var minLen = 5;
            var lenOff = 4;
            if (fromServer)
            {
                minLen = 8;
                lenOff = 3;
                if (ContinueBytes == null)
                    Console.WriteLine($"---{server} Server Packet(from:{srcIp})---");
            }
            else if (ContinueBytes == null)
            {
                Console.WriteLine($"---{server} Client Packet(to  :{dstIp})---");
            }

            var msg = tcpPacket.PayloadData;
            if (ContinueBytes != null) // try TCP Segmentation ReConstruction
            {
                var nextSeq = BeforePacket2.SequenceNumber + BeforePacket2.PayloadData.Length;
                if (tcpPacket.SequenceNumber != nextSeq)
                {
                    UnProcessingPackets.Add(tcpPacket);
                    return;
                }

                msg = ContinueBytes.Concat(tcpPacket.PayloadData).ToArray();
                while (UnProcessingPackets.Any())
                    try
                    {
                        var p = UnProcessingPackets.First(p => p.SequenceNumber == nextSeq);
                        msg = msg.Concat(p.PayloadData).ToArray();
                        nextSeq += p.PayloadData.Length;
                        UnProcessingPackets.Remove(p);
                    }
                    catch (InvalidOperationException)
                    {
                        break;
                    }

                ContinueBytes = null;
                BeforePacket2 = null;
            }
            else if (UnProcessedData != null) // try unprocessed data recovery
            {
                var nextSeq = BeforePacket2.SequenceNumber + BeforePacket2.PayloadData.Length;
                if (tcpPacket.SequenceNumber != nextSeq)
                {
                    UnProcessingPackets.Add(tcpPacket);
                    return;
                }

                try
                {
                    ParsePacket(UnProcessedData.Concat(msg).ToArray());
                    return;
                }
                catch (Exception)
                {
                    Console.WriteLine($"#Give Up Recover Data#");
                }
                finally
                {
                    UnProcessedData = null;
                }
            }

            ParsePacket(msg);

            void ParsePacket(byte[] msg)
            {
                while (msg.Length > minLen)
                {
                    var size = BitConverter.ToUInt16(new[] {msg[1], msg[2]}) + lenOff;
                    if (size > msg.Length)
                    {
                        ContinueBytes = msg;
                        BeforePacket2 = tcpPacket;
                        break;
                    }

                    Console.WriteLine($"---Message(Size:{size})---");
                    var data = msg.Take(size).ToArray();
                    msg = msg.Skip(size).ToArray();
                    if (fromServer)
                        HandleMessage(new PangServerMessage(data, key, server));
                    else
                        HandleMessage(new PangClientMessage(data, key, server));
                }

                if (msg.Any() && ContinueBytes == null)
                {
                    UnProcessedData = msg;
                    BeforePacket2 = tcpPacket;
                }
            }

            if (ContinueBytes == null && UnProcessedData == null && UnProcessingPackets.Any()
            ) // proceed UnProcessingPackets
            {
                var min = UnProcessingPackets.Min(p => p.SequenceNumber);
                HandleTcpPacket(UnProcessingPackets.First(p => p.SequenceNumber == min));
            }
        }

        public static byte[] UnProcessedData { get; set; }

        private static bool CheckCapture(IServer server, IPAddress ip, int port)
        {
            if (server == null)
                return false;
            return ip.Equals(server.IP) && port.Equals(server.Port);
        }

        private static byte[] ContinueBytes { get; set; } // for TCP Segmentation

        private static void HandleMessage(IPangMessage msg)
        {
            Console.Write(msg.Message.Take(160).ToArray().HexDump());
            Console.WriteLine();
            var basePath = Path.Combine(LaunchTime.ToString("s").Replace(':', '_'), msg.ServerType.ToString(),
                msg is PangServerMessage ? "Server" : "Client", msg.Id.ToString("X4"));
            var fileTime = DateTime.Now.ToString("s").Replace(':', '_');

            var out1 = new FileInfo(Path.Combine(basePath, fileTime + ".txt"));
            out1.Directory?.Create();
            File.WriteAllText(out1.FullName, msg.Message.HexDump());
            var out2 = new FileInfo(Path.Combine(basePath, "hex", fileTime + ".hex"));
            out2.Directory?.Create();
            File.WriteAllBytes(out2.FullName, msg.Message);
            // FileInfo out3 = new FileInfo(Path.Combine(Path.Combine(basePath, "raw"), fileTime + ".txt")); // encrypted data record
            // out3.Directory?.Create();
            // File.WriteAllText(out1.FullName, msg.RawMessage.HexDump());
            // FileInfo out4 = new FileInfo(Path.Combine(Path.Combine(basePath, "rawhex"), fileTime + ".hex"));
            // out4.Directory?.Create();
            // File.WriteAllBytes(out4.FullName, msg.RawMessage);
            switch (msg.ServerType)
            {
                case ServerTypeEnum.Login:
                    if (msg is PangServerMessage psm)
                        switch (psm.Id)
                        {
                            case 0x02: // GameServerList
                                var gameCount = psm.Message[2];
                                var data = psm.Message.Skip(3).ToArray();
                                for (var i = 0; i < gameCount; i++)
                                {
                                    var name = UsingEncode.GetString(data[0..40]).Trim('\0');
                                    var id = BitConverter.ToInt32(data[40..44], 0);
                                    var ip = IPAddress.Parse(UsingEncode.GetString(data[52..68]).Trim('\0'));
                                    var port = BitConverter.ToInt16(data[70..72]);
                                    var s = new GameServer(ip, port, name, id);
                                    GameServers.Add(s);
                                    BreakIpAddresses.Add(ip);
                                    ServerPorts.Add(port);
                                    data = data.Skip(92).ToArray();
                                }

                                break;
                            case 0x09: // MessageServerList
                                var msgCount = psm.Message[2];
                                var msgData = psm.Message.Skip(3).ToArray();
                                for (var i = 0; i < msgCount; i++)
                                {
                                    var name = UsingEncode.GetString(msgData[0..40]).Trim('\0');
                                    var id = BitConverter.ToInt32(msgData[40..44], 0);
                                    var ip = IPAddress.Parse(UsingEncode.GetString(msgData[52..68]).Trim('\0'));
                                    var port = BitConverter.ToInt16(msgData[70..72]);
                                    var s = new MessageServer(ip, port, name, id);
                                    MessageServers.Add(s);
                                    BreakIpAddresses.Add(ip);
                                    ServerPorts.Add(port);
                                    msgData = msgData.Skip(92).ToArray();
                                }

                                break;
                        }

                    break;
                case ServerTypeEnum.Game:
                    break;
                case ServerTypeEnum.Message:
                    break;
                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

        private static Encoding UsingEncode { get; } = Encoding.Default;
        private static IPAddress LoginServerIP { get; set; }
        private static int LoginServerPort { get; set; }
        private static List<GameServer> GameServers { get; } = new List<GameServer>();
        private static GameServer ConnectingGameServer { get; set; }
        private static List<MessageServer> MessageServers { get; } = new List<MessageServer>();
        private static MessageServer ConnectingMessageServer { get; set; }
        private static HashSet<IPAddress> BreakIpAddresses { get; } = new HashSet<IPAddress>();
        private static HashSet<int> ServerPorts { get; } = new HashSet<int>();
        private static DateTime LaunchTime { get; } = DateTime.Now;

        private static byte LoginKeyIndex
        {
            get => _loginKeyIndex;
            set
            {
                _loginKeyIndex = value;
                GotLoginKey = true;
            }
        }

        private static TcpPacket BeforePacket { get; set; }
        private static TcpPacket BeforePacket2 { get; set; }
        private static List<TcpPacket> UnProcessingPackets { get; } = new List<TcpPacket>();

        private static byte _loginKeyIndex;
        public static bool GotLoginKey { get; private set; }

        private static byte GameKeyIndex
        {
            get => _gameKeyIndex;
            set
            {
                _gameKeyIndex = value;
                GotGameKey = true;
            }
        }

        private static byte _gameKeyIndex;
        public static bool GotGameKey { get; private set; }

        private static byte MessageKeyIndex
        {
            get => _messageKeyIndex;
            set
            {
                _messageKeyIndex = value;
                GotMessageKey = true;
            }
        }

        private static byte _messageKeyIndex;
        public static bool GotMessageKey { get; private set; }
    }

    internal interface IServer
    {
        public IPAddress IP { get; }
        public int Port { get; }
    }

    internal class MessageServer : IServer
    {
        public MessageServer(IPAddress ip, int port, string name, int id)
        {
            IP = ip;
            Port = port;
            Name = name;
            ID = id;
        }

        public IPAddress IP { get; }
        public int Port { get; }
        public string Name { get; }
        public int ID { get; }
    }

    internal enum ServerTypeEnum
    {
        Unknown,
        Login,
        Game,
        Message
    }

    internal class GameServer : IServer
    {
        public GameServer(IPAddress ip, int port, string name, int id)
        {
            IP = ip;
            Port = port;
            Name = name;
            ID = id;
        }

        public IPAddress IP { get; }
        public int Port { get; }
        public string Name { get; }
        public int ID { get; }
    }

    internal interface IPangMessage
    {
        public short Id { get; }

        public byte[] Message { get; }

        public byte[] RawMessage { get; }

        public byte KeyIndex { get; }
        public byte Salt { get; }
        public byte Xor { get; }
        public ServerTypeEnum ServerType { get; }
    }

    internal class PangServerMessage : IPangMessage
    {
        public PangServerMessage(byte[] data, byte keyIndex, ServerTypeEnum server)
        {
            RawMessage = data;
            KeyIndex = keyIndex;
            ServerType = server;
            CompressedSize = BitConverter.ToInt16(new[] {RawMessage[1], RawMessage[2]}) - 5;
            Message = ServerCipher.Decrypt(RawMessage, KeyIndex);
        }

        public PangServerMessage(byte[] data, ServerTypeEnum server)
        {
            Message = data;
            ServerType = server;
        }

        public byte Num8 => RawMessage[4];
        public byte Num6 => RawMessage[5];
        public byte Num4 => RawMessage[6];
        public byte Num2 => RawMessage[7];
        public int CompressedSize { get; set; }

        public short Id => BitConverter.ToInt16(Message[..2]);
        public byte[] Message { get; }
        public byte[] RawMessage { get; }
        public byte KeyIndex { get; }
        public byte Salt => RawMessage[0];
        public byte Xor => RawMessage[3];
        public ServerTypeEnum ServerType { get; }
    }

    internal class PangClientMessage : IPangMessage
    {
        public PangClientMessage(byte[] data, byte keyIndex, ServerTypeEnum server)
        {
            RawMessage = data;
            KeyIndex = keyIndex;
            ServerType = server;
            MsgSize = BitConverter.ToInt16(new[] {RawMessage[1], RawMessage[2]}) - 1;
            Message = ClientCipher.Decrypt(data, KeyIndex);
        }

        public PangClientMessage(byte[] data)
        {
            Message = data;
        }

        public byte Empty => RawMessage[3];
        public int MsgSize { get; set; }
        public short Id => BitConverter.ToInt16(Message[..2]);
        public byte[] Message { get; }
        public byte[] RawMessage { get; }
        public byte KeyIndex { get; }
        public byte Salt => RawMessage[0];
        public byte Xor => RawMessage[4];
        public ServerTypeEnum ServerType { get; }
    }

    internal static class Utils
    {
        // this method from https://www.codeproject.com/Articles/36747/Quick-and-Dirty-HexDump-of-a-Byte-Array
        public static string HexDump(this byte[] bytes, int bytesPerLine = 16)
        {
            if (bytes == null) return "<null>";
            var bytesLength = bytes.Length;

            var HexChars = "0123456789ABCDEF".ToCharArray();

            var firstHexColumn =
                8 // 8 characters for the address
                + 3; // 3 spaces

            var firstCharColumn = firstHexColumn
                                  + bytesPerLine * 3 // - 2 digit for the hexadecimal value and 1 space
                                  + (bytesPerLine - 1) / 8 // - 1 extra space every 8 characters from the 9th
                                  + 2; // 2 spaces 

            var lineLength = firstCharColumn
                             + bytesPerLine // - characters to show the ascii value
                             + Environment.NewLine.Length; // Carriage return and line feed (should normally be 2)

            var line = (new string(' ', lineLength - Environment.NewLine.Length) + Environment.NewLine).ToCharArray();
            var expectedLines = (bytesLength + bytesPerLine - 1) / bytesPerLine;
            var result = new StringBuilder(expectedLines * lineLength);

            for (var i = 0; i < bytesLength; i += bytesPerLine)
            {
                line[0] = HexChars[(i >> 28) & 0xF];
                line[1] = HexChars[(i >> 24) & 0xF];
                line[2] = HexChars[(i >> 20) & 0xF];
                line[3] = HexChars[(i >> 16) & 0xF];
                line[4] = HexChars[(i >> 12) & 0xF];
                line[5] = HexChars[(i >> 8) & 0xF];
                line[6] = HexChars[(i >> 4) & 0xF];
                line[7] = HexChars[(i >> 0) & 0xF];

                var hexColumn = firstHexColumn;
                var charColumn = firstCharColumn;

                for (var j = 0; j < bytesPerLine; j++)
                {
                    if (j > 0 && (j & 7) == 0) hexColumn++;
                    if (i + j >= bytesLength)
                    {
                        line[hexColumn] = ' ';
                        line[hexColumn + 1] = ' ';
                        line[charColumn] = ' ';
                    }
                    else
                    {
                        var b = bytes[i + j];
                        line[hexColumn] = HexChars[(b >> 4) & 0xF];
                        line[hexColumn + 1] = HexChars[b & 0xF];
                        line[charColumn] = b < 32 ? '·' : (char) b;
                    }

                    hexColumn += 3;
                    charColumn++;
                }

                result.Append(line);
            }

            return result.ToString();
        }
    }
}