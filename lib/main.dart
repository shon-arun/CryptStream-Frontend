import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:local_auth/local_auth.dart';

void main() {
  runApp(
    const MaterialApp(
      debugShowCheckedModeBanner: false,
      home: BiometricGate(),
    ),
  );
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
    _authenticate();
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

  // Define your mandatory secondary security string here
  final String _secretPassphrase = "testadmin42626"; 

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
    // Metric fulfilled: Both fingerprint and string matched.
    // The image fetch sequence triggers here.
    if (_isFullyUnlocked) {
      return Scaffold(
        backgroundColor: Colors.black,
        body: Center(
          child: Image.network(
            'http://192.168.1.2:8000/',
            fit: BoxFit.contain,
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
              const Icon(
                Icons.password,
                size: 80,
                color: Colors.blueAccent,
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
                  backgroundColor: Colors.blueAccent,
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