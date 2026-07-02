import 'package:flutter/material.dart';

void main() {
  runApp(
    MaterialApp(
      debugShowCheckedModeBanner: false, 
      home: Scaffold(
        backgroundColor: Colors.black,
        body: Center(
          child: Image.network(
            'http://192.168.1.2:8000/',
            fit: BoxFit.contain,
          ),
        ),
      ),
    ),
  );
}