import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter/foundation.dart';
import 'package:local_auth/local_auth.dart';
import 'dart:typed_data';
import 'package:http/http.dart' as http;
import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:uuid/uuid.dart';
import 'dart:async';
import 'package:geolocator/geolocator.dart';
import 'dart:io';
import 'dart:math';
import 'package:image_picker/image_picker.dart';
import 'package:image/image.dart' as img;
import 'package:video_player/video_player.dart';

void main() {
  HttpOverrides.global = DevHttpOverrides();

  runApp(
    const MaterialApp(debugShowCheckedModeBanner: false, home: BiometricGate()),
  );
}

class DevHttpOverrides extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) {
    return super.createHttpClient(context)
      ..badCertificateCallback = (X509Certificate cert, String host, int port) {
        return host == "192.168.1.2";
      };
  }
}

// -------------------------------------------------------------
// CENTRALIZED LOCATION STREAM CACHE
// -------------------------------------------------------------
class LocationService {
  static Position? currentPosition;
  static StreamSubscription<Position>? _positionStreamSubscription;

  static Future<void> startStream() async {
    if (_positionStreamSubscription != null) return;

    currentPosition = await Geolocator.getCurrentPosition(
      desiredAccuracy: LocationAccuracy.high,
    );

    const LocationSettings locationSettings = LocationSettings(
      accuracy: LocationAccuracy.high,
      distanceFilter: 5,
    );

    _positionStreamSubscription =
        Geolocator.getPositionStream(locationSettings: locationSettings).listen(
          (Position position) {
            currentPosition = position;
          },
        );
  }

  static void stopStream() {
    _positionStreamSubscription?.cancel();
    _positionStreamSubscription = null;
  }
}

class LocationHeartbeat {
  static Timer? _timer;
  static VoidCallback? onForbidden;

  static void start() {
    if (_timer != null) return;
    _timer = Timer.periodic(const Duration(seconds: 10), (timer) async {
      try {
        if (LocationService.currentPosition == null) return;

        String deviceId = await DeviceIdentity.getDeviceId();

        final response = await http.post(
          Uri.parse('https://192.168.1.2/heartbeat'),
          headers: {"Content-Type": "application/json"},
          body: jsonEncode({
            "device_id": deviceId,
            "lat": LocationService.currentPosition!.latitude,
            "lon": LocationService.currentPosition!.longitude,
          }),
        );

        if (response.statusCode == 403) {
          onForbidden?.call();
        }
      } catch (e) {
        // Silently fail network drops in background
      }
    });
  }

  static void stop() {
    _timer?.cancel();
    _timer = null;
  }
}

class DeviceIdentity {
  static const _storage = FlutterSecureStorage(
    aOptions: AndroidOptions(encryptedSharedPreferences: true),
    iOptions: IOSOptions(
      accessibility: KeychainAccessibility.unlocked_this_device,
    ),
  );
  static final _algorithm = Ed25519();

  static Future<String> getDeviceId() async {
    String? deviceId = await _storage.read(key: 'device_id');
    if (deviceId == null) {
      deviceId = const Uuid().v4();
      await _storage.write(key: 'device_id', value: deviceId);
    }
    return deviceId;
  }

  static Future<void> generateAndStoreKeys() async {
    final storedPrivateKey = await _storage.read(key: 'device_private_key');
    if (storedPrivateKey == null) {
      final keyPair = await _algorithm.newKeyPair();
      final privateKeyBytes = await keyPair.extractPrivateKeyBytes();
      final publicKey = await keyPair.extractPublicKey();

      await _storage.write(
        key: 'device_private_key',
        value: base64Encode(privateKeyBytes),
      );
      await _storage.write(
        key: 'device_public_key',
        value: base64Encode(publicKey.bytes),
      );
    }
  }

  static Future<String> getPublicKeyString() async {
    String? publicKeyBase64 = await _storage.read(key: 'device_public_key');
    return publicKeyBase64 ?? "Key not generated";
  }

  static Future<String?> getPublicKey() async {
    return await _storage.read(key: 'device_public_key');
  }

  static Future<String?> getPrivateKey() async {
    final LocalAuthentication auth = LocalAuthentication();
    final bool canAuthenticateWithBiometrics = await auth.canCheckBiometrics;
    final bool canAuthenticate =
        canAuthenticateWithBiometrics || await auth.isDeviceSupported();

    if (!canAuthenticate) {
      throw Exception("Biometric hardware is required to release secure keys.");
    }

    final authenticated = await auth.authenticate(
      localizedReason: 'Authenticate to release your private key',
      options: const AuthenticationOptions(
        stickyAuth: true,
        biometricOnly: true,
      ),
    );

    if (!authenticated) throw Exception("Biometric authentication failed.");

    return await _storage.read(key: 'device_private_key');
  }
}

class BiometricGate extends StatefulWidget {
  const BiometricGate({super.key});
  @override
  State<BiometricGate> createState() => _BiometricGateState();
}

class _BiometricGateState extends State<BiometricGate> {
  final LocalAuthentication auth = LocalAuthentication();
  bool _isAuthenticated = false;
  String _statusMessage = "Initializing Security Enclave...";
  String _lockoutReason = "";

  @override
  void initState() {
    super.initState();
    _bootstrapEnclave();
  }

  Future<void> _bootstrapEnclave() async {
    try {
      await _verifyLocationEnclave();
      await _initializeIdentity();
      await _authenticate();
    } catch (e) {
      if (mounted) {
        setState(() {
          _lockoutReason = e.toString().replaceFirst('Exception: ', '');
        });
      }
    }
  }

  Future<void> _verifyLocationEnclave() async {
    setState(() => _statusMessage = "Verifying GPS Hardware...");
    bool serviceEnabled = await Geolocator.isLocationServiceEnabled();
    if (!serviceEnabled) {
      throw Exception("GPS hardware is disabled. Geofence cannot be verified.");
    }

    setState(() => _statusMessage = "Verifying OS Permissions...");
    LocationPermission permission = await Geolocator.checkPermission();
    if (permission == LocationPermission.denied) {
      permission = await Geolocator.requestPermission();
      if (permission == LocationPermission.denied) {
        throw Exception(
          "Location permissions denied. Geofence cannot be verified.",
        );
      }
    }

    if (permission == LocationPermission.deniedForever) {
      throw Exception(
        "Location permissions permanently denied. Geofence cannot be verified.",
      );
    }

    setState(
      () => _statusMessage = "Acquiring Enclave Coordinates (Stream)...",
    );

    await LocationService.startStream();
    if (LocationService.currentPosition == null) {
      throw Exception("Failed to acquire initial coordinate lock.");
    }
  }

  Future<void> _initializeIdentity() async {
    setState(() => _statusMessage = "Verifying Identity Keys...");
    try {
      await DeviceIdentity.generateAndStoreKeys();
    } catch (e) {
      throw Exception("Identity Generation Failed: $e");
    }
  }

  Future<void> _authenticate() async {
    bool authenticated = false;
    try {
      setState(() => _statusMessage = "Scanning Biometrics...");
      final bool canAuthenticate =
          await auth.canCheckBiometrics || await auth.isDeviceSupported();

      if (!canAuthenticate) {
        throw Exception("Biometric hardware not available or not configured.");
      }

      authenticated = await auth.authenticate(
        localizedReason: 'Please authenticate to access CryptStream',
        options: const AuthenticationOptions(
          stickyAuth: true,
          biometricOnly: true,
        ),
      );
    } on PlatformException catch (e) {
      if (mounted) {
        setState(() => _lockoutReason = "Biometric Error: ${e.message}");
      }
      return;
    } catch (e) {
      if (mounted) {
        setState(
          () => _lockoutReason = e.toString().replaceFirst('Exception: ', ''),
        );
      }
      return;
    }

    if (!mounted) return;

    if (authenticated) {
      setState(() {
        _isAuthenticated = true;
        _statusMessage = "Authenticated Successfully";
      });
    } else {
      setState(() => _lockoutReason = "Authentication Failed. Access Denied.");
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_isAuthenticated) return const PassphraseGate();

    if (_lockoutReason.isNotEmpty) {
      return Scaffold(
        backgroundColor: Colors.black,
        body: Center(
          child: Padding(
            padding: const EdgeInsets.all(24.0),
            child: Column(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                const Icon(Icons.gpp_bad, size: 80, color: Colors.red),
                const SizedBox(height: 24),
                const Text(
                  "HARD LOCKOUT",
                  style: TextStyle(
                    color: Colors.red,
                    fontSize: 22,
                    fontWeight: FontWeight.bold,
                    letterSpacing: 2,
                  ),
                ),
                const SizedBox(height: 16),
                Text(
                  _lockoutReason,
                  textAlign: TextAlign.center,
                  style: const TextStyle(color: Colors.white70, fontSize: 16),
                ),
                const SizedBox(height: 36),
                ElevatedButton.icon(
                  onPressed: () {
                    setState(() {
                      _lockoutReason = "";
                    });
                    _bootstrapEnclave();
                  },
                  icon: const Icon(Icons.refresh),
                  label: const Text("Retry Boot Sequence"),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.red[900],
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(
                      horizontal: 24,
                      vertical: 12,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      );
    }

    return Scaffold(
      backgroundColor: Colors.grey[900],
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(Icons.security, size: 80, color: Colors.redAccent),
              const SizedBox(height: 32),
              const CircularProgressIndicator(color: Colors.redAccent),
              const SizedBox(height: 24),
              Text(
                _statusMessage,
                textAlign: TextAlign.center,
                style: const TextStyle(color: Colors.white, fontSize: 16),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class PassphraseGate extends StatefulWidget {
  const PassphraseGate({super.key});
  @override
  State<PassphraseGate> createState() => _PassphraseGateState();
}

class _PassphraseGateState extends State<PassphraseGate> {
  final TextEditingController _controller = TextEditingController();
  bool _isBootstrapping = false;
  String _errorMessage = "";
  Future<Uint8List>? _bootstrapFuture;

  @override
  void initState() {
    super.initState();
    LocationHeartbeat.start();

    LocationHeartbeat.onForbidden = () {
      if (mounted && _isBootstrapping) {
        setState(() {
          _isBootstrapping = false;
          _errorMessage = "Access denied: Out of bounds. Session locked.";
          _controller.clear();
          _bootstrapFuture = null;
        });
      }
    };
  }

  void _submitPassphrase() {
    if (_controller.text.isNotEmpty) {
      setState(() {
        _isBootstrapping = true;
        _errorMessage = "";
        _bootstrapFuture = bootstrapSession(_controller.text);
      });
    } else {
      setState(() => _errorMessage = "Please enter a passphrase");
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    LocationHeartbeat.stop(); 
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (_isBootstrapping) {
      return Scaffold(
        backgroundColor: Colors.black,
        body: Center(
          child: FutureBuilder<Uint8List>(
            future: _bootstrapFuture,
            builder: (context, snapshot) {
              if (snapshot.connectionState == ConnectionState.waiting) {
                return const Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    CircularProgressIndicator(color: Colors.redAccent),
                    SizedBox(height: 24),
                    Text(
                      "Deriving Master Encryption Key (Argon2id)...\nPlease wait.",
                      textAlign: TextAlign.center,
                      style: TextStyle(color: Colors.white70),
                    ),
                  ],
                );
              } else if (snapshot.hasError) {
                return Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Text(
                        'Bootstrapping Failed.\n\nDetails: ${snapshot.error}',
                        style: const TextStyle(
                          color: Colors.redAccent,
                          fontSize: 16,
                        ),
                        textAlign: TextAlign.center,
                      ),
                      const SizedBox(height: 24),
                      ElevatedButton(
                        onPressed: () {
                          setState(() {
                            _isBootstrapping = false;
                            _controller.clear();
                            _bootstrapFuture = null;
                          });
                        },
                        child: const Text("Try Again"),
                      ),
                    ],
                  ),
                );
              } else if (snapshot.hasData) {
                return GalleryGridView(mek: snapshot.data!);
              }
              return const Text(
                "No data",
                style: TextStyle(color: Colors.white),
              );
            },
          ),
        ),
      );
    }

    return Scaffold(
      backgroundColor: Colors.grey[900],
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(32.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              FutureBuilder<String>(
                future: DeviceIdentity.getPublicKeyString(),
                builder: (context, snapshot) {
                  return Padding(
                    padding: const EdgeInsets.only(bottom: 24.0),
                    child: Column(
                      children: [
                        const Text(
                          "Device Public Key:",
                          style: TextStyle(color: Colors.white70, fontSize: 12),
                        ),
                        SelectableText(
                          snapshot.data ?? "Loading...",
                          style: const TextStyle(
                            color: Colors.redAccent,
                            fontSize: 10,
                          ),
                        ),
                      ],
                    ),
                  );
                },
              ),
              const Icon(Icons.password, size: 80, color: Colors.redAccent),
              const SizedBox(height: 24),
              const Text(
                "Enter Passphrase",
                style: TextStyle(color: Colors.white, fontSize: 18),
              ),
              const SizedBox(height: 16),
              TextField(
                controller: _controller,
                obscureText: true,
                style: const TextStyle(color: Colors.white),
                decoration: InputDecoration(
                  filled: true,
                  fillColor: Colors.grey[800],
                  border: const OutlineInputBorder(),
                  errorText: _errorMessage.isEmpty ? null : _errorMessage,
                ),
                onSubmitted: (_) => _submitPassphrase(),
              ),
              const SizedBox(height: 24),
              ElevatedButton.icon(
                onPressed: _submitPassphrase,
                icon: const Icon(Icons.login),
                label: const Text("Boot Session"),
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.redAccent,
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(
                    horizontal: 24,
                    vertical: 12,
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// -------------------------------------------------------------
// VFS DATA MODELS (Virtual File System)
// -------------------------------------------------------------

abstract class VfsNode {
  final String type; // 't'
  final Map<String, dynamic> metadata; // 'm'
  final List<String> pointers; // 'p'
  String nodeId = ""; // Transient property for VFS navigation

  VfsNode({required this.type, required this.metadata, required this.pointers});

  factory VfsNode.fromJson(Map<String, dynamic> json) {
    final t = json['t'] as String? ?? 'unknown';
    final m = json['m'] as Map<String, dynamic>? ?? {};
    final p = (json['p'] as List<dynamic>? ?? [])
        .map((e) => e.toString())
        .toList();

    if (t == 'd') return VfsDirectory(metadata: m, pointers: p);
    if (t == 'j') return VfsJpeg(metadata: m, pointers: p);
    if (t == 'v') return VfsVideo(metadata: m, pointers: p);
    return VfsGeneric(type: t, metadata: m, pointers: p);
  }

  Map<String, dynamic> toJson() => {'t': type, 'm': metadata, 'p': pointers};
}

class VfsGeneric extends VfsNode {
  VfsGeneric({
    required super.type,
    required super.metadata,
    required super.pointers,
  });
}

class VfsDirectory extends VfsNode {
  VfsDirectory({required super.metadata, required super.pointers})
    : super(type: 'd');
  String get name => metadata['n'] ?? 'Unnamed Directory';
}

class VfsJpeg extends VfsNode {
  VfsJpeg({required super.metadata, required super.pointers})
    : super(type: 'j');
  String get name => metadata['n'] ?? 'Unnamed Image';
  String get thumbnailBase64 => metadata['tb'] ?? '';
  String get assetKey => metadata['k'] ?? '';
}

class VfsVideo extends VfsNode {
  VfsVideo({required super.metadata, required super.pointers})
    : super(type: 'v');
  String get name => metadata['n'] ?? 'Unnamed Video';
  String get thumbnailBase64 => metadata['tb'] ?? '';
  String get assetKey => metadata['k'] ?? '';
  
  // Videos strictly enforce a file size property for the loopback server's Range requests
  int get size => metadata['s'] ?? (pointers.length * 512 * 1024); // Fallback assumption for old dummy videos
}

// -------------------------------------------------------------
// CORE CRYPTO LOGIC & ISOLATES
// -------------------------------------------------------------

Future<Uint8List> signChallenge(
  String challenge,
  String privateKeyBase64,
) async {
  final privateKeyBytes = base64Decode(privateKeyBase64);
  final keyPair = await Ed25519().newKeyPairFromSeed(privateKeyBytes);
  final signature = await Ed25519().sign(
    utf8.encode(challenge),
    keyPair: keyPair,
  );
  return Uint8List.fromList(signature.bytes);
}

Future<Map<String, double>> getCurrentLocation() async {
  if (LocationService.currentPosition == null) {
    LocationService.currentPosition = await Geolocator.getCurrentPosition(
      desiredAccuracy: LocationAccuracy.high,
    );
  }
  return {
    "lat": LocationService.currentPosition!.latitude,
    "lon": LocationService.currentPosition!.longitude,
  };
}

Future<Uint8List> bootstrapSession(String passphrase) async {
  String deviceId = await DeviceIdentity.getDeviceId();
  final loc = await getCurrentLocation();

  String? pubKeyBase64 = await DeviceIdentity.getPublicKey();
  if (pubKeyBase64 == null) throw Exception("Device identity not initialized");

  final registerRes = await http.post(
    Uri.parse('https://192.168.1.2/register'),
    headers: {"Content-Type": "application/json"},
    body: jsonEncode({"device_id": deviceId, "public_key": pubKeyBase64}),
  );
  if (registerRes.statusCode != 200) throw Exception("Registration failed");

  final registerData = jsonDecode(registerRes.body);
  final String vaultSaltB64 = registerData['vault_salt'];
  final Uint8List vaultSalt = base64Decode(vaultSaltB64);

  final challengeRes = await http.post(
    Uri.parse('https://192.168.1.2/request-challenge'),
    headers: {"Content-Type": "application/json"},
    body: jsonEncode({
      "device_id": deviceId,
      "lat": loc['lat'],
      "lon": loc['lon'],
    }),
  );
  if (challengeRes.statusCode != 200){
    throw Exception("Challenge request failed");
  }


  String challenge = jsonDecode(challengeRes.body)['challenge'];
  String? privKeyBase64 = await DeviceIdentity.getPrivateKey();
  if (privKeyBase64 == null) throw Exception("Device identity not initialized");

  Uint8List sig = await signChallenge(challenge, privKeyBase64);

  final verifyRes = await http.post(
    Uri.parse('https://192.168.1.2/verify'),
    headers: {"Content-Type": "application/json"},
    body: jsonEncode({
      "device_id": deviceId,
      "signature": base64Encode(sig),
      "lat": loc['lat'],
      "lon": loc['lon'],
    }),
  );
  if (verifyRes.statusCode != 200) throw Exception("Verification failed");

  final argon2 = Argon2id(
    memory: 262144,
    iterations: 3,
    parallelism: 1,
    hashLength: 32,
  );
  final derivedSecretKey = await argon2.deriveKey(
    secretKey: SecretKey(utf8.encode(passphrase)),
    nonce: vaultSalt,
  );

  final keyBytes = await derivedSecretKey.extractBytes();
  return Uint8List.fromList(keyBytes);
}

Future<dynamic> _decryptAndParseIsolate(Map<String, dynamic> args) async {
  final Uint8List mek = args['mek'];
  final Uint8List payload = args['payload'];

  Uint8List nonceBytes = payload.sublist(0, 12);
  Uint8List cipherTextBytes = payload.sublist(28, payload.length - 16);
  Uint8List macBytes = payload.sublist(payload.length - 16);

  final chachaCipher = Chacha20.poly1305Aead();
  final secretBox = SecretBox(
    cipherTextBytes,
    nonce: nonceBytes,
    mac: Mac(macBytes),
  );

  final decryptedBytes = await chachaCipher.decrypt(
    secretBox,
    secretKey: SecretKey(mek),
  );
  final decoded = jsonDecode(utf8.decode(decryptedBytes));

  if (decoded is List) return decoded.map((e) => VfsNode.fromJson(e)).toList();
  return VfsNode.fromJson(decoded);
}

Future<Uint8List> _serializeAndEncryptIsolate(Map<String, dynamic> args) async {
  final Uint8List mek = args['mek'];
  final Map<String, dynamic> jsonNode = args['jsonNode'];

  final plainText = utf8.encode(jsonEncode(jsonNode));
  final chachaCipher = Chacha20.poly1305Aead();
  final nonce = chachaCipher.newNonce();
  final secretBox = await chachaCipher.encrypt(
    plainText,
    secretKey: SecretKey(mek),
    nonce: nonce,
  );

  final builder = BytesBuilder();
  builder.add(secretBox.nonce);
  builder.add(Uint8List(16));
  builder.add(secretBox.cipherText);
  builder.add(secretBox.mac.bytes);
  return builder.toBytes();
}

Future<Uint8List> _encryptChunkIsolate(Map<String, dynamic> args) async {
  final Uint8List key = args['key'];
  final Uint8List data = args['data'];

  final chachaCipher = Chacha20.poly1305Aead();
  final nonce = chachaCipher.newNonce();
  final secretBox = await chachaCipher.encrypt(
    data,
    secretKey: SecretKey(key),
    nonce: nonce,
  );

  final builder = BytesBuilder();
  builder.add(secretBox.nonce);
  builder.add(secretBox.cipherText);
  builder.add(secretBox.mac.bytes);
  return builder.toBytes();
}

/// A specialized isolate function specifically for the LocalVideoProxy to fetch single blocks on-demand
Future<Uint8List> _fetchAndDecryptSingleChunkIsolate(Map<String, dynamic> args) async {
  HttpOverrides.global = DevHttpOverrides(); // Needed since isolate runs independently

  final String ptr = args['pointer'];
  final Uint8List assetKey = args['assetKey'];
  final String deviceId = args['deviceId'];
  final double lat = args['lat'];
  final double lon = args['lon'];

  final response = await http.post(
    Uri.parse('https://192.168.1.2/payload/fetch'),
    headers: {"Content-Type": "application/json"},
    body: jsonEncode({
      "device_id": deviceId,
      "lat": lat,
      "lon": lon,
      "pointer": ptr,
    }),
  );

  if (response.statusCode != 200) {
    throw Exception("Failed to fetch chunk: $ptr");
  }

  final payload = response.bodyBytes;
  final nonceBytes = payload.sublist(0, 12);
  final cipherTextBytes = payload.sublist(12, payload.length - 16);
  final macBytes = payload.sublist(payload.length - 16);

  final chachaCipher = Chacha20.poly1305Aead();
  final secretBox = SecretBox(
    cipherTextBytes,
    nonce: nonceBytes,
    mac: Mac(macBytes),
  );
  
  final decryptedBytes = await chachaCipher.decrypt(
    secretBox,
    secretKey: SecretKey(assetKey),
  );

  return Uint8List.fromList(decryptedBytes);
}

Future<Uint8List> _downloadAndDecryptChunksIsolate(
  Map<String, dynamic> args,
) async {
  HttpOverrides.global = DevHttpOverrides();

  final List<String> pointers = List<String>.from(args['pointers']);
  final Uint8List assetKey = args['assetKey'];
  final String deviceId = args['deviceId'];
  final double lat = args['lat'];
  final double lon = args['lon'];

  final builder = BytesBuilder();
  final chachaCipher = Chacha20.poly1305Aead();

  for (String ptr in pointers) {
    final response = await http.post(
      Uri.parse('https://192.168.1.2/payload/fetch'),
      headers: {"Content-Type": "application/json"},
      body: jsonEncode({
        "device_id": deviceId,
        "lat": lat,
        "lon": lon,
        "pointer": ptr,
      }),
    );

    if (response.statusCode != 200){
      throw Exception("Failed to fetch chunk: $ptr");
    }

    final payload = response.bodyBytes;
    final nonceBytes = payload.sublist(0, 12);
    final cipherTextBytes = payload.sublist(12, payload.length - 16);
    final macBytes = payload.sublist(payload.length - 16);

    final secretBox = SecretBox(
      cipherTextBytes,
      nonce: nonceBytes,
      mac: Mac(macBytes),
    );
    final decryptedBytes = await chachaCipher.decrypt(
      secretBox,
      secretKey: SecretKey(assetKey),
    );

    builder.add(decryptedBytes);
  }

  return builder.toBytes();
}

Future<String> _generateThumbnailIsolate(String filePath) async {
  final fileBytes = await File(filePath).readAsBytes();
  final img.Image? decodedImage = img.decodeImage(fileBytes);
  if (decodedImage == null) return ""; 

  final img.Image resized = img.copyResize(decodedImage, width: 150);
  final List<int> compressedJpg = img.encodeJpg(resized, quality: 60);

  return base64Encode(compressedJpg);
}

// -------------------------------------------------------------
// LOCAL LOOPBACK PROXY (Phase 2 Video Streaming)
// -------------------------------------------------------------
class LocalVideoProxy {
  HttpServer? _server;
  final VfsVideo videoNode;
  final Uint8List assetKey;
  final String deviceId;
  final double lat;
  final double lon;

  static const int chunkSize = 512 * 1024; // 512KB matches backend ingest

  LocalVideoProxy({
    required this.videoNode,
    required this.assetKey,
    required this.deviceId,
    required this.lat,
    required this.lon,
  });

  Future<String> start() async {
    // Bind to a random ephemeral port on localhost
    _server = await HttpServer.bind(InternetAddress.loopbackIPv4, 0);
    _server!.listen(_handleRequest);
    // Explicitly append the specific file pointer as a query parameter as requested
    return 'http://127.0.0.1:${_server!.port}/stream?ptr=${videoNode.nodeId}';
  }

  void stop() {
    _server?.close(force: true);
  }

  void _handleRequest(HttpRequest request) async {
    final response = request.response;
    final int videoSize = videoNode.size;
    
    try {
      String? rangeHeader = request.headers.value('range');
      int start = 0;
      int end = videoSize - 1;
      bool isPartial = false;

      // Parse the OS media player's HTTP Range header to know what exact bytes it wants
      if (rangeHeader != null && rangeHeader.startsWith('bytes=')) {
        isPartial = true;
        final parts = rangeHeader.substring(6).split('-');
        if (parts[0].isNotEmpty) start = int.parse(parts[0]);
        if (parts.length > 1 && parts[1].isNotEmpty) {
          end = int.parse(parts[1]);
        }
      }

      if (end >= videoSize) end = videoSize - 1;

      // Feed specific Video HTTP Headers back to trick the native OS Player
      response.headers.add('Accept-Ranges', 'bytes');
      response.headers.contentType = ContentType('video', 'mp4');

      if (isPartial) {
        response.statusCode = HttpStatus.partialContent;
        response.headers.add('Content-Range', 'bytes $start-$end/$videoSize');
        response.headers.add('Content-Length', (end - start + 1).toString());
      } else {
        response.statusCode = HttpStatus.ok;
        response.headers.add('Content-Length', videoSize.toString());
      }

      // Mathematical mapping of byte ranges -> Cryptographic Chunks
      int currentByte = start;
      
      while (currentByte <= end) {
        int chunkIndex = currentByte ~/ chunkSize;
        
        // Prevent array out-of-bounds if file sizes don't perfectly match math padding
        if (chunkIndex >= videoNode.pointers.length) break; 
        
        String pointer = videoNode.pointers[chunkIndex];

        // Decrypt only the specific 512KB chunk containing our requested bytes via Isolate
        Uint8List decrypted = await compute(_fetchAndDecryptSingleChunkIsolate, {
          'pointer': pointer,
          'assetKey': assetKey,
          'deviceId': deviceId,
          'lat': lat,
          'lon': lon,
        });

        int chunkStartPos = chunkIndex * chunkSize;
        int sliceStart = currentByte - chunkStartPos;
        int sliceEnd = sliceStart + (end - currentByte + 1);
        if (sliceEnd > decrypted.length) sliceEnd = decrypted.length;

        // Pipe the exact plaintext byte sequence seamlessly into the HTTP stream
        response.add(decrypted.sublist(sliceStart, sliceEnd));

        currentByte += (sliceEnd - sliceStart);
      }
      
      await response.close();
      
    } catch (e) {
      // The video player will forcefully abort requests as the user scrubs the timeline.
      // We gracefully swallow the socket exceptions.
      try {
        await response.close();
      } catch (_) {}
    }
  }
}

// -------------------------------------------------------------
// MAIN GALLERY VIEW & INGESTION
// -------------------------------------------------------------

class GalleryGridView extends StatefulWidget {
  final Uint8List mek;
  const GalleryGridView({super.key, required this.mek});
  @override
  State<GalleryGridView> createState() => _GalleryGridViewState();
}

class _GalleryGridViewState extends State<GalleryGridView> {
  bool _isLoading = true;
  String _loadingText = "Fetching & Decrypting Gallery...";
  List<VfsNode> _items = [];
  String _error = "";

  List<String> _navigationStack = [];
  String _currentPointer = "root";
  String _currentFolderName = "Encrypted Gallery";

  @override
  void initState() {
    super.initState();
    _fetchDirectory();
  }

  Future<void> _fetchDirectory() async {
    setState(() {
      _isLoading = true;
      _loadingText = "Syncing Directory Tree...";
      _error = "";
    });

    try {
      String deviceId = await DeviceIdentity.getDeviceId();
      final loc = await getCurrentLocation();

      final response = await http.post(
        Uri.parse('https://192.168.1.2/payload/fetch'),
        headers: {"Content-Type": "application/json"},
        body: jsonEncode({
          "device_id": deviceId,
          "lat": loc['lat'],
          "lon": loc['lon'],
          "pointer": _currentPointer,
        }),
      );

      if (response.statusCode == 404 && _currentPointer == "root") {
        setState(() {
          _items = [];
          _isLoading = false;
          _error = "Vault not initialized.";
        });
        return;
      }
      if (response.statusCode == 404) {
        setState(() {
          _items = [];
          _isLoading = false;
        });
        return;
      }
      if (response.statusCode != 200) {
        throw Exception('Failed to fetch directory: ${response.statusCode}');
      }

      final dirNode = await compute(_decryptAndParseIsolate, {
        'mek': widget.mek,
        'payload': response.bodyBytes,
      });

      if (dirNode is VfsDirectory) {
        _currentFolderName = dirNode.name;
        List<Future<VfsNode?>> fetchFutures = dirNode.pointers.map((ptr) async {
          final childRes = await http.post(
            Uri.parse('https://192.168.1.2/payload/fetch'),
            headers: {"Content-Type": "application/json"},
            body: jsonEncode({
              "device_id": deviceId,
              "lat": loc['lat'],
              "lon": loc['lon'],
              "pointer": ptr,
            }),
          );
          if (childRes.statusCode == 200) {
            final childNode = await compute(_decryptAndParseIsolate, {
              'mek': widget.mek,
              'payload': childRes.bodyBytes,
            });
            if (childNode is VfsNode) {
              childNode.nodeId = ptr;
              return childNode;
            }
          }
          return null;
        }).toList();

        final results = await Future.wait(fetchFutures);
        setState(() {
          _items = results.whereType<VfsNode>().toList();
          _isLoading = false;
        });
      } else {
        setState(() {
          _items = [];
          _isLoading = false;
        });
      }
    } catch (e) {
      setState(() {
        _error = e.toString();
        _isLoading = false;
      });
    }
  }

  void _navigateBack() {
    if (_navigationStack.isNotEmpty) {
      setState(() {
        _currentPointer = _navigationStack.removeLast();
      });
      _fetchDirectory();
    }
  }

  Future<void> _showCreateFolderDialog() async {
    TextEditingController nameController = TextEditingController();

    return showDialog(
      context: context,
      builder: (context) {
        return AlertDialog(
          backgroundColor: Colors.grey[900],
          title: const Text(
            "New Folder",
            style: TextStyle(color: Colors.white),
          ),
          content: TextField(
            controller: nameController,
            autofocus: true,
            style: const TextStyle(color: Colors.white),
            decoration: const InputDecoration(
              hintText: "Enter folder name",
              hintStyle: TextStyle(color: Colors.white54),
              enabledBorder: UnderlineInputBorder(
                borderSide: BorderSide(color: Colors.white24),
              ),
              focusedBorder: UnderlineInputBorder(
                borderSide: BorderSide(color: Colors.blueAccent),
              ),
            ),
          ),
          actions: [
            TextButton(
              child: const Text(
                "Cancel",
                style: TextStyle(color: Colors.white54),
              ),
              onPressed: () => Navigator.pop(context),
            ),
            TextButton(
              child: const Text(
                "Create",
                style: TextStyle(color: Colors.blueAccent),
              ),
              onPressed: () {
                if (nameController.text.trim().isNotEmpty) {
                  Navigator.pop(context);
                  _createFolder(nameController.text.trim());
                }
              },
            ),
          ],
        );
      },
    );
  }

  Future<void> _createFolder(String folderName) async {
    setState(() {
      _isLoading = true;
      _loadingText = "Creating Folder...";
    });
    try {
      String deviceId = await DeviceIdentity.getDeviceId();
      final loc = await getCurrentLocation();

      final newFolderNode = VfsDirectory(
        metadata: {'n': folderName},
        pointers: [],
      );
      final newFolderPointer = const Uuid().v4().replaceAll('-', '');
      final encryptedNewFolder = await compute(_serializeAndEncryptIsolate, {
        'mek': widget.mek,
        'jsonNode': newFolderNode.toJson(),
      });

      await http.post(
        Uri.parse('https://192.168.1.2/payload/upload'),
        headers: {"Content-Type": "application/json"},
        body: jsonEncode({
          "device_id": deviceId,
          "lat": loc['lat'],
          "lon": loc['lon'],
          "pointer": newFolderPointer,
          "base64_blob": base64Encode(encryptedNewFolder),
        }),
      );

      final parentFetchRes = await http.post(
        Uri.parse('https://192.168.1.2/payload/fetch'),
        headers: {"Content-Type": "application/json"},
        body: jsonEncode({
          "device_id": deviceId,
          "lat": loc['lat'],
          "lon": loc['lon'],
          "pointer": _currentPointer,
        }),
      );

      if (parentFetchRes.statusCode == 200) {
        final parentNode = await compute(_decryptAndParseIsolate, {
          'mek': widget.mek,
          'payload': parentFetchRes.bodyBytes,
        });
        if (parentNode is VfsDirectory) {
          parentNode.pointers.add(newFolderPointer);
          final updatedParentBlob = await compute(_serializeAndEncryptIsolate, {
            'mek': widget.mek,
            'jsonNode': parentNode.toJson(),
          });

          await http.post(
            Uri.parse('https://192.168.1.2/payload/upload'),
            headers: {"Content-Type": "application/json"},
            body: jsonEncode({
              "device_id": deviceId,
              "lat": loc['lat'],
              "lon": loc['lon'],
              "pointer": _currentPointer,
              "base64_blob": base64Encode(updatedParentBlob),
            }),
          );
        }
      }
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Folder Created!'),
            backgroundColor: Colors.green,
          ),
        );
      }
      _fetchDirectory();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Failed to create folder: $e'),
            backgroundColor: Colors.red,
          ),
        );
      }
      setState(() {
        _isLoading = false;
      });
    }
  }

  Future<void> _initializeRootNode() async {
    try {
      final rootNode = VfsDirectory(
        metadata: {'n': 'My Encrypted Vault'},
        pointers: [],
      );
      final encryptedBlob = await compute(_serializeAndEncryptIsolate, {
        'mek': widget.mek,
        'jsonNode': rootNode.toJson(),
      });

      String deviceId = await DeviceIdentity.getDeviceId();
      final loc = await getCurrentLocation();

      final response = await http.post(
        Uri.parse('https://192.168.1.2/payload/upload'),
        headers: {"Content-Type": "application/json"},
        body: jsonEncode({
          "device_id": deviceId,
          "lat": loc['lat'],
          "lon": loc['lon'],
          "pointer": "root",
          "base64_blob": base64Encode(encryptedBlob),
        }),
      );

      if (response.statusCode == 200 && mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Root Node Initialized!'),
            backgroundColor: Colors.green,
          ),
        );
        _fetchDirectory();
      }
    } catch (e) {
      setState(() {
        _error = e.toString();
        _isLoading = false;
      });
    }
  }

  Future<void> _pickAndUploadMedia() async {
    final picker = ImagePicker();
    final XFile? pickedFile = await picker.pickMedia();

    if (pickedFile == null) return;

    setState(() {
      _isLoading = true;
      _loadingText = "Processing & Encrypting Media...";
    });
    try {
      final File realFile = File(pickedFile.path);

      await _ingestMediaFile(realFile, _currentPointer);

      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Upload Complete!'),
            backgroundColor: Colors.green,
          ),
        );
      }
      _fetchDirectory();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Upload failed: $e'),
            backgroundColor: Colors.red,
          ),
        );
      }
      setState(() {
        _isLoading = false;
      });
    }
  }

  Future<void> _ingestMediaFile(File file, String parentPointer) async {
    final random = Random.secure();

    final assetKey = Uint8List.fromList(
      List.generate(32, (_) => random.nextInt(256)),
    );

    final bool isVideo = file.path.toLowerCase().endsWith('.mp4') || file.path.toLowerCase().endsWith('.mov');

    String thumbnailBase64 = "";
    if (!isVideo) {
      thumbnailBase64 = await compute(
        _generateThumbnailIsolate,
        file.path,
      );
    }

    final int chunkSize = 512 * 1024;
    final int fileLength = await file.length();
    List<String> chunkPointers = [];

    String deviceId = await DeviceIdentity.getDeviceId();
    final loc = await getCurrentLocation();

    final raf = await file.open();
    for (int i = 0; i < fileLength; i += chunkSize) {
      final chunk = await raf.read(chunkSize);
      final chunkPointer = const Uuid().v4().replaceAll('-', '');
      chunkPointers.add(chunkPointer);

      final encryptedChunkBlob = await compute(_encryptChunkIsolate, {
        'key': assetKey,
        'data': chunk,
      });

      final res = await http.post(
        Uri.parse('https://192.168.1.2/payload/upload'),
        headers: {"Content-Type": "application/json"},
        body: jsonEncode({
          "device_id": deviceId,
          "lat": loc['lat'],
          "lon": loc['lon'],
          "pointer": chunkPointer,
          "base64_blob": base64Encode(encryptedChunkBlob),
        }),
      );
      if (res.statusCode != 200) {
        throw Exception(
          "Server rejected chunk with status ${res.statusCode}: ${res.body}",
        );
      }
    }
    await raf.close();

    VfsNode mediaNode;
    if (isVideo) {
      mediaNode = VfsVideo(
        metadata: {
          'n': file.uri.pathSegments.last,
          'tb': thumbnailBase64,
          'k': base64Encode(assetKey),
          's': fileLength, // Store the exact size in bytes specifically for Video Range proxy mapping
        },
        pointers: chunkPointers,
      );
    } else {
      mediaNode = VfsJpeg(
        metadata: {
          'n': file.uri.pathSegments.last,
          'tb': thumbnailBase64,
          'k': base64Encode(assetKey),
        },
        pointers: chunkPointers,
      );
    }

    final mediaPointer = const Uuid().v4().replaceAll('-', '');
    final encryptedMediaNode = await compute(_serializeAndEncryptIsolate, {
      'mek': widget.mek,
      'jsonNode': mediaNode.toJson(),
    });

    await http.post(
      Uri.parse('https://192.168.1.2/payload/upload'),
      headers: {"Content-Type": "application/json"},
      body: jsonEncode({
        "device_id": deviceId,
        "lat": loc['lat'],
        "lon": loc['lon'],
        "pointer": mediaPointer,
        "base64_blob": base64Encode(encryptedMediaNode),
      }),
    );

    final parentFetchRes = await http.post(
      Uri.parse('https://192.168.1.2/payload/fetch'),
      headers: {"Content-Type": "application/json"},
      body: jsonEncode({
        "device_id": deviceId,
        "lat": loc['lat'],
        "lon": loc['lon'],
        "pointer": parentPointer,
      }),
    );

    if (parentFetchRes.statusCode == 200) {
      final parentNode = await compute(_decryptAndParseIsolate, {
        'mek': widget.mek,
        'payload': parentFetchRes.bodyBytes,
      });
      if (parentNode is VfsDirectory) {
        parentNode.pointers.add(mediaPointer);
        final updatedParentBlob = await compute(_serializeAndEncryptIsolate, {
          'mek': widget.mek,
          'jsonNode': parentNode.toJson(),
        });

        await http.post(
          Uri.parse('https://192.168.1.2/payload/upload'),
          headers: {"Content-Type": "application/json"},
          body: jsonEncode({
            "device_id": deviceId,
            "lat": loc['lat'],
            "lon": loc['lon'],
            "pointer": parentPointer,
            "base64_blob": base64Encode(updatedParentBlob),
          }),
        );
      }
    }
  }

  Future<void> _deleteNode(VfsNode nodeToDelete) async {
    setState(() {
      _isLoading = true;
      _loadingText = "Deleting & Syncing Vault...";
    });
    try {
      String deviceId = await DeviceIdentity.getDeviceId();
      final loc = await getCurrentLocation();

      final parentFetchRes = await http.post(
        Uri.parse('https://192.168.1.2/payload/fetch'),
        headers: {"Content-Type": "application/json"},
        body: jsonEncode({
          "device_id": deviceId,
          "lat": loc['lat'],
          "lon": loc['lon'],
          "pointer": _currentPointer,
        }),
      );

      if (parentFetchRes.statusCode == 200) {
        final parentNode = await compute(_decryptAndParseIsolate, {
          'mek': widget.mek,
          'payload': parentFetchRes.bodyBytes,
        });

        if (parentNode is VfsDirectory) {
          parentNode.pointers.remove(nodeToDelete.nodeId);

          final updatedParentBlob = await compute(_serializeAndEncryptIsolate, {
            'mek': widget.mek,
            'jsonNode': parentNode.toJson(),
          });
          final updateRes = await http.post(
            Uri.parse('https://192.168.1.2/payload/upload'),
            headers: {"Content-Type": "application/json"},
            body: jsonEncode({
              "device_id": deviceId,
              "lat": loc['lat'],
              "lon": loc['lon'],
              "pointer": _currentPointer,
              "base64_blob": base64Encode(updatedParentBlob),
            }),
          );
          if (updateRes.statusCode != 200)
            throw Exception(
              "Failed to structurally unlink the node from parent.",
            );
        }
      }

      List<String> pointersToPurge = [nodeToDelete.nodeId];
      pointersToPurge.addAll(nodeToDelete.pointers);

      final deleteRes = await http.post(
        Uri.parse('https://192.168.1.2/payload/delete'),
        headers: {"Content-Type": "application/json"},
        body: jsonEncode({
          "device_id": deviceId,
          "lat": loc['lat'],
          "lon": loc['lon'],
          "pointers": pointersToPurge,
        }),
      );

      if (deleteRes.statusCode != 200)
        throw Exception("Backend failed to purge encrypted blocks.");

      if (mounted)
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Deletion & Purge Complete!'),
            backgroundColor: Colors.green,
          ),
        );
      _fetchDirectory();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Delete failed: $e'),
            backgroundColor: Colors.red,
          ),
        );
      }
      setState(() {
        _isLoading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return PopScope(
      canPop: _navigationStack.isEmpty,
      onPopInvoked: (didPop) {
        if (didPop) return;
        _navigateBack();
      },
      child: Scaffold(
        backgroundColor: Colors.black,
        appBar: AppBar(
          title: Text(
            _currentFolderName,
            style: const TextStyle(color: Colors.redAccent),
          ),
          backgroundColor: Colors.grey[900],
          elevation: 0,
          leading: _navigationStack.isNotEmpty
              ? IconButton(
                  icon: const Icon(Icons.arrow_back),
                  onPressed: _navigateBack,
                )
              : null,
          actions: [
            IconButton(
              icon: const Icon(Icons.create_new_folder),
              onPressed: _showCreateFolderDialog,
            ),
            IconButton(
              icon: const Icon(Icons.refresh),
              onPressed: _fetchDirectory,
            ),
          ],
        ),
        floatingActionButton: FloatingActionButton.extended(
          onPressed: _pickAndUploadMedia,
          backgroundColor: Colors.redAccent,
          icon: const Icon(Icons.add, color: Colors.black),
          label: const Text(
            "Upload Media",
            style: TextStyle(color: Colors.black, fontWeight: FontWeight.bold),
          ),
        ),
        body: _isLoading
            ? Center(
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    const CircularProgressIndicator(color: Colors.redAccent),
                    const SizedBox(height: 16),
                    Text(
                      _loadingText,
                      style: const TextStyle(color: Colors.white54),
                    ),
                  ],
                ),
              )
            : _error.isNotEmpty
            ? Center(
                child: Padding(
                  padding: const EdgeInsets.all(24.0),
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Text(
                        _error,
                        textAlign: TextAlign.center,
                        style: const TextStyle(
                          color: Colors.redAccent,
                          fontSize: 16,
                        ),
                      ),
                      const SizedBox(height: 24),
                      ElevatedButton.icon(
                        onPressed: _initializeRootNode,
                        icon: const Icon(Icons.create_new_folder),
                        label: const Text("Initialize Root Node"),
                        style: ElevatedButton.styleFrom(
                          backgroundColor: Colors.teal,
                          foregroundColor: Colors.white,
                        ),
                      ),
                    ],
                  ),
                ),
              )
            : _items.isEmpty
            ? const Center(
                child: Text(
                  "Vault is empty.",
                  style: TextStyle(color: Colors.white54),
                ),
              )
            : GridView.builder(
                padding: const EdgeInsets.all(16),
                gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                  crossAxisCount: 4,
                  crossAxisSpacing: 4,
                  mainAxisSpacing: 4,
                ),
                itemCount: _items.length,
                itemBuilder: (context, index) {
                  final item = _items[index];
                  Widget contentWidget;

                  if (item is VfsDirectory) {
                    contentWidget = Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        const Icon(Icons.folder, size: 48, color: Colors.amber),
                        const SizedBox(height: 8),
                        Text(
                          item.name,
                          style: const TextStyle(
                            color: Colors.white,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        Text(
                          "${item.pointers.length} items",
                          style: const TextStyle(
                            color: Colors.white54,
                            fontSize: 11,
                          ),
                        ),
                      ],
                    );
                  } else if (item is VfsJpeg) {
                    Widget imageWidget = const Icon(
                      Icons.image,
                      size: 48,
                      color: Colors.blueAccent,
                    );
                    if (item.thumbnailBase64.isNotEmpty) {
                      try {
                        imageWidget = Image.memory(
                          base64Decode(item.thumbnailBase64),
                          fit: BoxFit.cover,
                          width: double.infinity,
                        );
                      } catch (_) {}
                    }
                    contentWidget = Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      children: [
                        Expanded(
                          child: ClipRRect(
                            borderRadius: const BorderRadius.vertical(
                              top: Radius.circular(12),
                            ),
                            child: imageWidget,
                          ),
                        ),
                        Padding(
                          padding: const EdgeInsets.all(8.0),
                          child: Text(
                            item.name,
                            style: const TextStyle(
                              color: Colors.white,
                              fontSize: 12,
                            ),
                            overflow: TextOverflow.ellipsis,
                            textAlign: TextAlign.center,
                          ),
                        ),
                      ],
                    );
                  } else if (item is VfsVideo) {
                    contentWidget = Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        const Icon(
                          Icons.movie,
                          size: 48,
                          color: Colors.deepPurpleAccent,
                        ),
                        const SizedBox(height: 8),
                        Padding(
                          padding: const EdgeInsets.symmetric(horizontal: 8.0),
                          child: Text(
                            item.name,
                            style: const TextStyle(
                              color: Colors.white,
                              fontSize: 12,
                            ),
                            overflow: TextOverflow.ellipsis,
                            textAlign: TextAlign.center,
                          ),
                        ),
                      ],
                    );
                  } else {
                    contentWidget = const Center(
                      child: Text(
                        "Unknown node",
                        style: TextStyle(color: Colors.white54),
                      ),
                    );
                  }

                  return InkWell(
                    onTap: () {
                      if (item is VfsDirectory) {
                        setState(() {
                          _navigationStack.add(_currentPointer);
                          _currentPointer = item.nodeId;
                        });
                        _fetchDirectory();
                      } else if (item is VfsJpeg) {
                        Navigator.push(
                          context,
                          MaterialPageRoute(
                            builder: (context) => ImageViewerScreen(item: item),
                          ),
                        );
                      } else if (item is VfsVideo) {
                        // Launch the new Loopback Video Player
                        Navigator.push(
                          context,
                          MaterialPageRoute(
                            builder: (context) => VideoViewerScreen(item: item),
                          ),
                        );
                      }
                    },
                    onLongPress: () {
                      showDialog(
                        context: context,
                        builder: (BuildContext ctx) {
                          final itemName = (item is VfsDirectory)
                              ? item.name
                              : (item is VfsJpeg ? item.name : (item is VfsVideo ? item.name : 'this item'));
                          return AlertDialog(
                            backgroundColor: Colors.grey[900],
                            title: const Text(
                              "Delete Item?",
                              style: TextStyle(color: Colors.white),
                            ),
                            content: Text(
                              "Are you sure you want to permanently delete '$itemName' and physically purge all of its encrypted blocks from the backend?",
                              style: const TextStyle(color: Colors.white70),
                            ),
                            actions: [
                              TextButton(
                                onPressed: () => Navigator.of(ctx).pop(),
                                child: const Text(
                                  "Cancel",
                                  style: TextStyle(color: Colors.white54),
                                ),
                              ),
                              TextButton(
                                onPressed: () {
                                  Navigator.of(ctx).pop();
                                  _deleteNode(item);
                                },
                                child: const Text(
                                  "Delete & Purge",
                                  style: TextStyle(color: Colors.redAccent),
                                ),
                              ),
                            ],
                          );
                        },
                      );
                    },
                    child: Card(
                      color: Colors.grey[850],
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: contentWidget,
                    ),
                  );
                },
              ),
      ),
    );
  }
}

// -------------------------------------------------------------
// IMAGE VIEWER SCREEN (Read Pipeline)
// -------------------------------------------------------------

class ImageViewerScreen extends StatefulWidget {
  final VfsJpeg item;
  const ImageViewerScreen({super.key, required this.item});

  @override
  State<ImageViewerScreen> createState() => _ImageViewerScreenState();
}

class _ImageViewerScreenState extends State<ImageViewerScreen> {
  Uint8List? _highResBytes;
  String _error = "";

  @override
  void initState() {
    super.initState();
    _fetchAndDecryptFullImage();
  }

  Future<void> _fetchAndDecryptFullImage() async {
    try {
      String deviceId = await DeviceIdentity.getDeviceId();
      final loc = await getCurrentLocation();
      final Uint8List assetKey = base64Decode(widget.item.assetKey);

      final assembledBytes = await compute(_downloadAndDecryptChunksIsolate, {
        'pointers': widget.item.pointers,
        'assetKey': assetKey,
        'deviceId': deviceId,
        'lat': loc['lat'],
        'lon': loc['lon'],
      });

      setState(() {
        _highResBytes = assembledBytes;
      });
    } catch (e) {
      setState(() {
        _error = e.toString();
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        title: Text(
          widget.item.name,
          style: const TextStyle(color: Colors.white, fontSize: 14),
        ),
        backgroundColor: Colors.black,
        elevation: 0,
      ),
      body: Center(
        child: _error.isNotEmpty
            ? Padding(
                padding: const EdgeInsets.all(16.0),
                child: Text(
                  'Decryption Error: $_error',
                  style: const TextStyle(color: Colors.redAccent),
                ),
              )
            : _highResBytes == null
            ? const Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  CircularProgressIndicator(color: Colors.blueAccent),
                  SizedBox(height: 16),
                  Text(
                    "Streaming Encrypted Chunks...",
                    style: TextStyle(color: Colors.white54),
                  ),
                ],
              )
            : Image.memory(_highResBytes!, fit: BoxFit.contain),
      ),
    );
  }
}

// -------------------------------------------------------------
// VIDEO VIEWER SCREEN (Local Loopback Streaming)
// -------------------------------------------------------------

class VideoViewerScreen extends StatefulWidget {
  final VfsVideo item;
  const VideoViewerScreen({super.key, required this.item});

  @override
  State<VideoViewerScreen> createState() => _VideoViewerScreenState();
}

class _VideoViewerScreenState extends State<VideoViewerScreen> {
  VideoPlayerController? _controller;
  LocalVideoProxy? _proxy;
  bool _isInitialized = false;
  String _error = "";

  @override
  void initState() {
    super.initState();
    _startProxyAndPlayer();
  }

  Future<void> _startProxyAndPlayer() async {
    try {
      String deviceId = await DeviceIdentity.getDeviceId();
      final loc = await getCurrentLocation();
      final Uint8List assetKey = base64Decode(widget.item.assetKey);

      _proxy = LocalVideoProxy(
        videoNode: widget.item,
        assetKey: assetKey,
        deviceId: deviceId,
        lat: loc['lat']!,
        lon: loc['lon']!,
      );

      // Start the local interceptor server
      String proxyUrl = await _proxy!.start();

      // Point the native OS Video Player directly at our Dart proxy server loopback address
      _controller = VideoPlayerController.networkUrl(Uri.parse(proxyUrl))
        ..initialize().then((_) {
          if (mounted) {
            setState(() {
              _isInitialized = true;
            });
            _controller!.play();
          }
        });
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = e.toString();
        });
      }
    }
  }

  @override
  void dispose() {
    _controller?.dispose();
    _proxy?.stop(); // Safely kill the loopback server when the user leaves the screen
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Colors.black,
      appBar: AppBar(
        title: Text(
          widget.item.name,
          style: const TextStyle(color: Colors.white, fontSize: 14),
        ),
        backgroundColor: Colors.black,
        elevation: 0,
      ),
      body: Center(
        child: _error.isNotEmpty
            ? Padding(
                padding: const EdgeInsets.all(16.0),
                child: Text(
                  'Proxy Error: $_error',
                  style: const TextStyle(color: Colors.redAccent),
                ),
              )
            : _isInitialized
            ? AspectRatio(
                aspectRatio: _controller!.value.aspectRatio,
                child: Stack(
                  alignment: Alignment.bottomCenter,
                  children: [
                    VideoPlayer(_controller!),
                    _ControlsOverlay(controller: _controller!),
                    VideoProgressIndicator(_controller!, allowScrubbing: true),
                  ],
                ),
              )
            : const Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  CircularProgressIndicator(color: Colors.deepPurpleAccent),
                  SizedBox(height: 16),
                  Text(
                    "Spinning up Loopback Proxy...",
                    style: TextStyle(color: Colors.white54),
                  ),
                ],
              ),
      ),
    );
  }
}

// Simple Play/Pause Overlay UI for the Video
class _ControlsOverlay extends StatelessWidget {
  const _ControlsOverlay({required this.controller});
  final VideoPlayerController controller;

  @override
  Widget build(BuildContext context) {
    return Stack(
      children: <Widget>[
        AnimatedSwitcher(
          duration: const Duration(milliseconds: 50),
          reverseDuration: const Duration(milliseconds: 200),
          child: controller.value.isPlaying
              ? const SizedBox.shrink()
              : const ColoredBox(
                  color: Colors.black26,
                  child: Center(
                    child: Icon(
                      Icons.play_arrow,
                      color: Colors.white,
                      size: 100.0,
                      semanticLabel: 'Play',
                    ),
                  ),
                ),
        ),
        GestureDetector(
          onTap: () {
            controller.value.isPlaying ? controller.pause() : controller.play();
          },
        ),
      ],
    );
  }
}