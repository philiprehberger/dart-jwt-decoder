import 'dart:convert';

import 'package:philiprehberger_jwt_decoder/jwt_decoder.dart';

void main() {
  // Create a sample JWT for demonstration
  final header = base64Url.encode(utf8.encode('{"alg":"HS256","typ":"JWT"}'));
  final now = DateTime.now().toUtc();
  final exp = now.add(Duration(hours: 1)).millisecondsSinceEpoch ~/ 1000;
  final iat = now.millisecondsSinceEpoch ~/ 1000;
  final payload = base64Url.encode(utf8.encode(
    '{"sub":"user-123","iss":"example.com","iat":$iat,"exp":$exp,"role":"admin"}',
  ));
  final token = '$header.$payload.signature';

  // Decode
  final decoded = JwtDecoder.decode(token);
  print('Subject: ${decoded.subject}');       // user-123
  print('Issuer: ${decoded.issuer}');         // example.com
  print('Expires: ${decoded.expiration}');

  // Check expiration
  print('Expired: ${JwtDecoder.isExpired(token)}'); // false

  // Time to expiry
  final remaining = JwtDecoder.timeToExpiry(token);
  print('Expires in: ${remaining?.inMinutes} minutes');

  // Custom claims
  print('Role: ${decoded.claim<String>("role")}'); // admin
}
