import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:local_auth/local_auth.dart';
import 'dart:typed_data';
import 'package:http/http.dart' as http;
import 'package:encrypt/encrypt.dart' as encrypt;
import 'dart:convert';
import 'package:cryptography/cryptography.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:uuid/uuid.dart';

void main() {
  runApp(
    const MaterialApp(
      debugShowCheckedModeBanner: false,
      home: BiometricGate(),
    ),
  );
}

class DeviceIdentity {
  static const _storage = FlutterSecureStorage();
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
        value: base64Encode(privateKeyBytes)
      );
      await _storage.write(
        key: 'device_public_key', 
        value: base64Encode(publicKey.bytes)
      );
    }
  }

  static Future<String> getPublicKeyString() async {
  String? publicKeyBase64 = await _storage.read(key: 'device_public_key');
  return publicKeyBase64 ?? "Key not generated";
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
  String _statusMessage = "Authentication Required";

  @override
  void initState() {
    super.initState();
    _initializeIdentity();
    _authenticate();
  }

  Future<void> _initializeIdentity() async {
    try {
      await DeviceIdentity.generateAndStoreKeys();
    } catch (e) {
      print("Error generating device identity: $e");
    }
  }

  Future<void> _authenticate() async {
    bool authenticated = false;
    try {
      setState(() {
        _statusMessage = "Scanning...";
      });

      final bool canAuthenticateWithBiometrics = await auth.canCheckBiometrics;
      final bool canAuthenticate = canAuthenticateWithBiometrics || await auth.isDeviceSupported();

      if (!canAuthenticate) {
        setState(() {
          _statusMessage = "Biometric hardware not available or not configured.";
        });
        return;
      }

      // Trigger the fingerprint system prompt
      authenticated = await auth.authenticate(
        localizedReason: 'Please authenticate to access CryptStream',
        options: const AuthenticationOptions(
          stickyAuth: true,
          biometricOnly: true,
        ),
      );
    } on PlatformException catch (e) {
      setState(() {
        _statusMessage = "Error: ${e.message}";
      });
      return;
    }

    if (!mounted) return;

    if (authenticated) {
      setState(() {
        _isAuthenticated = true;
        _statusMessage = "Authenticated Successfully";
      });
    } else {
      setState(() {
        _statusMessage = "Authentication Failed. Try again.";
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_isAuthenticated) {
      return const PassphraseGate();
    }

    return Scaffold(
      backgroundColor: Colors.grey[900],
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Icon(
                Icons.lock_outline,
                size: 80,
                color: Colors.redAccent,
              ),
              const SizedBox(height: 24),
              Text(
                _statusMessage,
                textAlign: TextAlign.center,
                style: const TextStyle(color: Colors.white, fontSize: 18),
              ),
              const SizedBox(height: 36),
              ElevatedButton.icon(
                onPressed: _authenticate,
                icon: const Icon(Icons.fingerprint),
                label: const Text("Retry Scan"),
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.redAccent,
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
                ),
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
  bool _isFullyUnlocked = false;
  String _errorMessage = "";

  final String _secretPassphrase = "testadmin42636"; 

  void _verifyPassphrase() {
    if (_controller.text == _secretPassphrase) {
      setState(() {
        _isFullyUnlocked = true;
      });
    } else {
      setState(() {
        _errorMessage = "Incorrect passphrase";
        _controller.clear();
      });
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (_isFullyUnlocked) {
      return Scaffold(
        backgroundColor: Colors.black,
        body: Center(
          child: FutureBuilder<Uint8List>(
            future: fetchAndDecryptImage(),
            builder: (context, snapshot) {
              if (snapshot.connectionState == ConnectionState.waiting) {
                return const CircularProgressIndicator(color: Colors.blueAccent);
              } else if (snapshot.hasError) {
                return Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Text(
                    'Error: ${snapshot.error}',
                    style: const TextStyle(color: Colors.redAccent, fontSize: 16),
                    textAlign: TextAlign.center,
                  ),
                );
              } else if (snapshot.hasData) {
                return Image.memory(
                  snapshot.data!,
                  fit: BoxFit.contain,
                );
              }
              return const Text("No data", style: TextStyle(color: Colors.white));
            },
          ),
        ),
      );
    }

    // Secondary Locked UI State
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
                        const Text("Device Public Key:", style: TextStyle(color: Colors.white70, fontSize: 12)),
                        SelectableText(
                          snapshot.data ?? "Loading...",
                          style: const TextStyle(color: Colors.redAccent, fontSize: 10),
                        ),
                      ],
                    ),
                  );
                },
              ),
              const Icon(
                Icons.password,
                size: 80,
                color: Colors.redAccent,
              ),
              const SizedBox(height: 24),
              const Text(
                "Enter Passphrase",
                style: TextStyle(color: Colors.white, fontSize: 18),
              ),
              const SizedBox(height: 16),
              TextField(
                controller: _controller,
                obscureText: true, // Hides the typed characters
                style: const TextStyle(color: Colors.white),
                decoration: InputDecoration(
                  filled: true,
                  fillColor: Colors.grey[800],
                  border: const OutlineInputBorder(),
                  errorText: _errorMessage.isEmpty ? null : _errorMessage,
                ),
                onSubmitted: (_) => _verifyPassphrase(), // Triggers on keyboard "Enter"
              ),
              const SizedBox(height: 24),
              ElevatedButton.icon(
                onPressed: _verifyPassphrase,
                icon: const Icon(Icons.login),
                label: const Text("Unlock Stream"),
                style: ElevatedButton.styleFrom(
                  backgroundColor: Colors.redAccent,
                  foregroundColor: Colors.white,
                  padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 12),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

Future<Uint8List> fetchAndDecryptImage() async {
  String deviceId = await DeviceIdentity.getDeviceId();
  
  final challengeRes = await http.get(
    Uri.parse('http://192.168.1.2:8000/request-challenge/$deviceId')
  );
  if (challengeRes.statusCode != 200) throw Exception("Failed to get challenge");
  
  String challenge = jsonDecode(challengeRes.body)['challenge'];
  
  String? privKeyBase64 = await const FlutterSecureStorage().read(key: 'device_private_key');
  if (privKeyBase64 == null) throw Exception("Device identity not initialized");
  
  Uint8List sig = await signChallenge(challenge, privKeyBase64);
  
  final verifyRes = await http.post(
    Uri.parse('http://192.168.1.2:8000/verify/$deviceId'),
    headers: {"Content-Type": "application/json"},
    body: jsonEncode({"signature": base64Encode(sig)}),
  );
  if (verifyRes.statusCode != 200) throw Exception("Verification failed");
  
  final response = await http.get(
    Uri.parse('http://192.168.1.2:8000/?device_id=$deviceId')
  );

  if (response.statusCode != 200) {
    throw Exception('Failed to fetch payload: ${response.statusCode}');
  }

  Uint8List fullPayload = response.bodyBytes;

  Uint8List ivBytes = fullPayload.sublist(0, 16);
  Uint8List cipherTextBytes = fullPayload.sublist(16);

  final keyString = "MySecret32ByteHardcodedKeyHere42";
  final key = encrypt.Key.fromUtf8(keyString);
  final iv = encrypt.IV(ivBytes);

  final encrypter = encrypt.Encrypter(
    encrypt.AES(key, mode: encrypt.AESMode.cbc, padding: 'PKCS7')
  );

  final encryptedData = encrypt.Encrypted(cipherTextBytes);
  final decryptedBytes = encrypter.decryptBytes(encryptedData, iv: iv);

  return Uint8List.fromList(decryptedBytes);
}