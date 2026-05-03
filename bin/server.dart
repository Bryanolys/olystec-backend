import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart';
import 'package:shelf_router/shelf_router.dart';
import 'package:crypto/crypto.dart';

// ── JSON file "database" ──────────────────────────────────────────────────────
// Persiste cada tabela num arquivo data/<table>.json.
// Não requer nenhuma instalação externa — funciona em qualquer máquina.

class _Db {
  final String _dir;

  _Db(this._dir) {
    Directory(_dir).createSync(recursive: true);
  }

  List<Map<String, dynamic>> _read(String table) {
    final f = File('$_dir/$table.json');
    if (!f.existsSync()) return [];
    try {
      return (jsonDecode(f.readAsStringSync()) as List)
          .cast<Map<String, dynamic>>();
    } catch (_) {
      return [];
    }
  }

  void _save(String table, List<Map<String, dynamic>> rows) =>
      File('$_dir/$table.json')
          .writeAsStringSync(const JsonEncoder.withIndent('  ').convert(rows));

  List<Map<String, dynamic>> find(String table,
      {bool Function(Map<String, dynamic>)? where}) {
    final rows = _read(table);
    return where == null ? rows : rows.where(where).toList();
  }

  Map<String, dynamic>? findOne(String table,
      {required bool Function(Map<String, dynamic>) where}) =>
      find(table, where: where).firstOrNull;

  Map<String, dynamic> insert(String table, Map<String, dynamic> data) {
    final rows = _read(table);
    final nextId = rows.isEmpty
        ? 1
        : rows
                .map((r) => (r['id'] as num?)?.toInt() ?? 0)
                .reduce((a, b) => a > b ? a : b) +
            1;
    final row = {
      'id': nextId,
      'created_at': DateTime.now().toUtc().toIso8601String(),
      ...data,
    };
    rows.add(row);
    _save(table, rows);
    return row;
  }

  bool update(String table, Map<String, dynamic> patch,
      {required bool Function(Map<String, dynamic>) where}) {
    final rows = _read(table);
    var changed = false;
    for (var i = 0; i < rows.length; i++) {
      if (where(rows[i])) {
        rows[i] = {
          ...rows[i],
          ...patch,
          'updated_at': DateTime.now().toUtc().toIso8601String(),
        };
        changed = true;
      }
    }
    if (changed) _save(table, rows);
    return changed;
  }

  int delete(String table,
      {required bool Function(Map<String, dynamic>) where}) {
    final rows = _read(table);
    final before = rows.length;
    rows.removeWhere(where);
    if (rows.length != before) _save(table, rows);
    return before - rows.length;
  }
}

final _db = _Db('data');

// ── Utilidades ────────────────────────────────────────────────────────────────

String _hash(String s) => sha256.convert(utf8.encode(s)).toString();

String _otp() =>
    List.generate(6, (_) => Random.secure().nextInt(10)).join();

Response _json(int status, Map<String, dynamic> body) => Response(
      status,
      body: jsonEncode(body),
      headers: {'Content-Type': 'application/json'},
    );

Future<Map<String, dynamic>?> _parseBody(Request req) async {
  try {
    return jsonDecode(await req.readAsString()) as Map<String, dynamic>;
  } catch (_) {
    return null;
  }
}

// ── Auth: /register ───────────────────────────────────────────────────────────

Future<Response> _register(Request req) async {
  final b = await _parseBody(req);
  if (b == null) return _json(400, {'message': 'JSON inválido'});

  final name  = (b['name']     as String?)?.trim();
  final email = (b['email']    as String?)?.trim().toLowerCase();
  final pass  = b['password']  as String?;

  if ([name, email, pass].any((v) => v == null || v!.isEmpty)) {
    return _json(400, {'message': 'Preencha todos os campos'});
  }
  if (!email!.contains('@')) {
    return _json(400, {'message': 'Informe um e-mail válido'});
  }
  if (_db.findOne('users', where: (r) => r['email'] == email) != null) {
    return _json(409, {'message': 'Este e-mail já está cadastrado'});
  }

  _db.insert('users', {
    'name': name,
    'email': email,
    'password_hash': _hash(pass!),
    'active': true,
  });

  _db.insert('notifications', {
    'email': email,
    'type': 'welcome',
    'title': 'Bem-vindo à OlysTech! 🎉',
    'body': 'Sua conta foi criada com sucesso. Explore as melhores ofertas!',
    'read': false,
  });

  return _json(201, {
    'message': 'Cadastro realizado com sucesso',
    'user': {'name': name, 'email': email},
  });
}

// ── Auth: /login ──────────────────────────────────────────────────────────────

Future<Response> _login(Request req) async {
  final b = await _parseBody(req);
  if (b == null) return _json(400, {'message': 'JSON inválido'});

  final email = (b['email']    as String?)?.trim().toLowerCase();
  final pass  = b['password']  as String?;

  if ([email, pass].any((v) => v == null || v!.isEmpty)) {
    return _json(400, {'message': 'Preencha todos os campos'});
  }

  final user = _db.findOne('users',
      where: (r) => r['email'] == email && r['password_hash'] == _hash(pass!));
  if (user == null) {
    return _json(401, {'message': 'E-mail ou senha incorretos'});
  }

  _db.insert('sessions', {
    'user_id': user['id'],
    'email': email,
    'ip': req.headers['x-forwarded-for'] ?? 'local',
  });

  return _json(200, {
    'user': {'name': user['name'], 'email': user['email']},
  });
}

// ── Auth: /forgot-password ────────────────────────────────────────────────────

Future<Response> _forgotPassword(Request req) async {
  final b = await _parseBody(req);
  if (b == null) return _json(400, {'message': 'JSON inválido'});

  final email = (b['email'] as String?)?.trim().toLowerCase();
  if (email == null || !email.contains('@')) {
    return _json(400, {'message': 'Informe um e-mail válido.'});
  }

  if (_db.findOne('users', where: (r) => r['email'] == email) == null) {
    return _json(200, {
      'message': 'Se este e-mail estiver cadastrado, você receberá o código.'
    });
  }

  final code      = _otp();
  final expiresAt = DateTime.now().toUtc().add(const Duration(minutes: 15));

  _db.delete('reset_tokens', where: (r) => r['email'] == email);
  _db.insert('reset_tokens', {
    'email': email,
    'code': code,
    'expires_at': expiresAt.toIso8601String(),
  });

  stderr.writeln('[DEV] Código para $email: $code (válido 15 min)');

  return _json(200, {
    'message': 'Código enviado.',
    'dev_code': code,
  });
}

// ── Auth: /verify-code ────────────────────────────────────────────────────────

Future<Response> _verifyCode(Request req) async {
  final b = await _parseBody(req);
  if (b == null) return _json(400, {'message': 'JSON inválido'});

  final email = (b['email'] as String?)?.trim().toLowerCase();
  final code  = (b['code']  as String?)?.trim();

  if (email == null || code == null || code.length != 6) {
    return _json(400, {'message': 'Dados inválidos.'});
  }

  final token = _db.findOne('reset_tokens',
      where: (r) => r['email'] == email && r['code'] == code);
  if (token == null) {
    return _json(400, {'message': 'Código inválido ou expirado.'});
  }

  if (DateTime.now().toUtc().isAfter(DateTime.parse(token['expires_at'] as String))) {
    _db.delete('reset_tokens', where: (r) => r['email'] == email);
    return _json(400, {'message': 'Código expirado. Solicite um novo.'});
  }

  return _json(200, {'message': 'Código válido.'});
}

// ── Auth: /reset-password ─────────────────────────────────────────────────────

Future<Response> _resetPassword(Request req) async {
  final b = await _parseBody(req);
  if (b == null) return _json(400, {'message': 'JSON inválido'});

  final email = (b['email']    as String?)?.trim().toLowerCase();
  final code  = (b['code']     as String?)?.trim();
  final pass  = b['password']  as String?;

  if (email == null || code == null || code.length != 6 ||
      pass == null || pass.length < 6) {
    return _json(400, {'message': 'Dados inválidos.'});
  }

  final token = _db.findOne('reset_tokens',
      where: (r) => r['email'] == email && r['code'] == code);
  if (token == null) {
    return _json(400, {'message': 'Código inválido ou expirado.'});
  }
  if (DateTime.now().toUtc().isAfter(DateTime.parse(token['expires_at'] as String))) {
    _db.delete('reset_tokens', where: (r) => r['email'] == email);
    return _json(400, {'message': 'Código expirado. Solicite um novo.'});
  }

  _db.update('users', {'password_hash': _hash(pass)},
      where: (r) => r['email'] == email);
  _db.delete('reset_tokens', where: (r) => r['email'] == email);

  return _json(200, {'message': 'Senha redefinida com sucesso.'});
}

// ── Favoritos ─────────────────────────────────────────────────────────────────

Future<Response> _getFavorites(Request req) async {
  final email = req.url.queryParameters['email'];
  if (email == null || email.isEmpty) {
    return _json(400, {'message': 'E-mail obrigatório'});
  }
  final favs = _db.find('favorites', where: (r) => r['email'] == email);
  return _json(200, {'favorites': favs});
}

Future<Response> _addFavorite(Request req) async {
  final b = await _parseBody(req);
  if (b == null) return _json(400, {'message': 'JSON inválido'});

  final email     = (b['email']      as String?)?.trim().toLowerCase();
  final productId = b['product_id']  as String?;
  if (email == null || productId == null) {
    return _json(400, {'message': 'Dados inválidos'});
  }
  if (_db.findOne('favorites',
          where: (r) => r['email'] == email && r['product_id'] == productId) !=
      null) {
    return _json(200, {'message': 'Já está nos favoritos'});
  }

  final fav = _db.insert('favorites', {
    'email': email,
    'product_id': productId,
    'product_name': b['product_name'] ?? '',
    'price': b['price'],
  });
  return _json(201, {'favorite': fav});
}

Future<Response> _removeFavorite(Request req, String productId) async {
  final email = req.url.queryParameters['email'];
  if (email == null || email.isEmpty) {
    return _json(400, {'message': 'E-mail obrigatório'});
  }
  _db.delete('favorites',
      where: (r) => r['email'] == email && r['product_id'] == productId);
  return _json(200, {'message': 'Removido dos favoritos'});
}

// ── Alertas de Preço ──────────────────────────────────────────────────────────

Future<Response> _getAlerts(Request req) async {
  final email = req.url.queryParameters['email'];
  if (email == null || email.isEmpty) {
    return _json(400, {'message': 'E-mail obrigatório'});
  }
  final alerts = _db.find('price_alerts', where: (r) => r['email'] == email);
  return _json(200, {'alerts': alerts});
}

Future<Response> _createAlert(Request req) async {
  final b = await _parseBody(req);
  if (b == null) return _json(400, {'message': 'JSON inválido'});

  final email       = (b['email']        as String?)?.trim().toLowerCase();
  final productId   = b['product_id']    as String?;
  final targetPrice = (b['target_price'] as num?)?.toDouble();

  if (email == null || productId == null || targetPrice == null) {
    return _json(400, {'message': 'Dados inválidos'});
  }

  final alert = _db.insert('price_alerts', {
    'email': email,
    'product_id': productId,
    'product_name': b['product_name'] ?? '',
    'current_price': b['current_price'],
    'target_price': targetPrice,
    'active': true,
  });
  return _json(201, {'alert': alert});
}

Future<Response> _deleteAlert(Request req, String id) async {
  final idInt = int.tryParse(id);
  if (idInt == null) return _json(400, {'message': 'ID inválido'});
  _db.delete('price_alerts', where: (r) => r['id'] == idInt);
  return _json(200, {'message': 'Alerta removido'});
}

// ── Pedidos ───────────────────────────────────────────────────────────────────

Future<Response> _getOrders(Request req) async {
  final email = req.url.queryParameters['email'];
  if (email == null || email.isEmpty) {
    return _json(400, {'message': 'E-mail obrigatório'});
  }
  final orders = _db.find('orders', where: (r) => r['email'] == email);
  final result = orders.map((o) {
    final items = _db.find('order_items',
        where: (r) => r['order_id'] == o['id']);
    return {...o, 'items': items};
  }).toList();
  return _json(200, {'orders': result});
}

Future<Response> _createOrder(Request req) async {
  final b = await _parseBody(req);
  if (b == null) return _json(400, {'message': 'JSON inválido'});

  final email = (b['email'] as String?)?.trim().toLowerCase();
  final items = b['items'] as List?;
  final total = (b['total'] as num?)?.toDouble();

  if (email == null || items == null || items.isEmpty || total == null) {
    return _json(400, {'message': 'Dados inválidos'});
  }

  final order = _db.insert('orders', {
    'email': email,
    'total': total,
    'status': 'pending',
    'address_id': b['address_id'],
    'payment_method': b['payment_method'] ?? 'credit_card',
  });

  for (final raw in items) {
    final item = raw as Map<String, dynamic>;
    _db.insert('order_items', {
      'order_id': order['id'],
      'product_id': '${item['product_id']}',
      'product_name': item['product_name'] ?? '',
      'store': item['store'] ?? '',
      'price': (item['price'] as num?)?.toDouble() ?? 0.0,
      'quantity': (item['quantity'] as num?)?.toInt() ?? 1,
    });
  }

  _db.insert('notifications', {
    'email': email,
    'type': 'order',
    'title': 'Pedido #${order['id']} confirmado!',
    'body': 'Seu pedido de R\$ ${total.toStringAsFixed(2)} foi realizado com sucesso.',
    'read': false,
  });

  return _json(201, {'order': order});
}

// ── Endereços ─────────────────────────────────────────────────────────────────

Future<Response> _getAddresses(Request req) async {
  final email = req.url.queryParameters['email'];
  if (email == null || email.isEmpty) {
    return _json(400, {'message': 'E-mail obrigatório'});
  }
  return _json(200, {
    'addresses': _db.find('addresses', where: (r) => r['email'] == email),
  });
}

Future<Response> _createAddress(Request req) async {
  final b = await _parseBody(req);
  if (b == null) return _json(400, {'message': 'JSON inválido'});

  final email = (b['email'] as String?)?.trim().toLowerCase();
  if (email == null || email.isEmpty) {
    return _json(400, {'message': 'E-mail obrigatório'});
  }

  // Se for padrão, desmarcar os outros
  if (b['is_default'] == true) {
    _db.update('addresses', {'is_default': false},
        where: (r) => r['email'] == email);
  }

  final addr = _db.insert('addresses', {
    'email': email,
    'label': b['label'] ?? 'Casa',
    'recipient': b['recipient'] ?? '',
    'street': b['street'] ?? '',
    'number': b['number'] ?? '',
    'complement': b['complement'] ?? '',
    'neighborhood': b['neighborhood'] ?? '',
    'city': b['city'] ?? '',
    'state': b['state'] ?? '',
    'zip_code': b['zip_code'] ?? '',
    'is_default': b['is_default'] ?? false,
  });
  return _json(201, {'address': addr});
}

Future<Response> _updateAddress(Request req, String id) async {
  final b = await _parseBody(req);
  if (b == null) return _json(400, {'message': 'JSON inválido'});
  final idInt = int.tryParse(id);
  if (idInt == null) return _json(400, {'message': 'ID inválido'});
  _db.update('addresses', b, where: (r) => r['id'] == idInt);
  return _json(200, {'message': 'Endereço atualizado'});
}

Future<Response> _deleteAddress(Request req, String id) async {
  final idInt = int.tryParse(id);
  if (idInt == null) return _json(400, {'message': 'ID inválido'});
  _db.delete('addresses', where: (r) => r['id'] == idInt);
  return _json(200, {'message': 'Endereço removido'});
}

// ── Avaliações ────────────────────────────────────────────────────────────────

Future<Response> _getReviews(Request req, String productId) async {
  final reviews = _db.find('reviews',
      where: (r) => r['product_id'] == productId);
  final avg = reviews.isEmpty
      ? 0.0
      : reviews.map((r) => (r['rating'] as num).toDouble()).reduce((a, b) => a + b) /
          reviews.length;
  return _json(200, {
    'reviews': reviews,
    'average': double.parse(avg.toStringAsFixed(1)),
    'count': reviews.length,
  });
}

Future<Response> _createReview(Request req) async {
  final b = await _parseBody(req);
  if (b == null) return _json(400, {'message': 'JSON inválido'});

  final email     = (b['email']      as String?)?.trim().toLowerCase();
  final productId = b['product_id']  as String?;
  final rating    = (b['rating']     as num?)?.toInt();

  if (email == null || productId == null || rating == null ||
      rating < 1 || rating > 5) {
    return _json(400, {'message': 'Dados inválidos (nota entre 1 e 5)'});
  }

  // Uma avaliação por produto por usuário
  _db.delete('reviews',
      where: (r) => r['email'] == email && r['product_id'] == productId);

  final review = _db.insert('reviews', {
    'email': email,
    'product_id': productId,
    'rating': rating,
    'comment': (b['comment'] as String?)?.trim() ?? '',
  });
  return _json(201, {'review': review});
}

// ── Notificações ──────────────────────────────────────────────────────────────

Future<Response> _getNotifications(Request req) async {
  final email = req.url.queryParameters['email'];
  if (email == null || email.isEmpty) {
    return _json(400, {'message': 'E-mail obrigatório'});
  }
  final notifs = _db.find('notifications',
      where: (r) => r['email'] == email)
    ..sort((a, b) =>
        (b['created_at'] as String).compareTo(a['created_at'] as String));
  return _json(200, {'notifications': notifs});
}

Future<Response> _markRead(Request req, String id) async {
  final idInt = int.tryParse(id);
  if (idInt == null) return _json(400, {'message': 'ID inválido'});
  _db.update('notifications', {'read': true},
      where: (r) => r['id'] == idInt);
  return _json(200, {'message': 'Notificação marcada como lida'});
}

// ── Perfil do usuário ─────────────────────────────────────────────────────────

Future<Response> _getProfile(Request req) async {
  final email = req.url.queryParameters['email'];
  if (email == null || email.isEmpty) {
    return _json(400, {'message': 'E-mail obrigatório'});
  }
  final user = _db.findOne('users', where: (r) => r['email'] == email);
  if (user == null) return _json(404, {'message': 'Usuário não encontrado'});
  final safe = Map<String, dynamic>.from(user)..remove('password_hash');
  return _json(200, {'user': safe});
}

Future<Response> _updateProfile(Request req) async {
  final b = await _parseBody(req);
  if (b == null) return _json(400, {'message': 'JSON inválido'});
  final email = (b['email'] as String?)?.trim().toLowerCase();
  if (email == null || email.isEmpty) {
    return _json(400, {'message': 'E-mail obrigatório'});
  }
  final allowed = <String, dynamic>{};
  if (b['name'] != null) allowed['name'] = (b['name'] as String).trim();
  if (b['phone'] != null) allowed['phone'] = b['phone'];
  if (b['avatar_url'] != null) allowed['avatar_url'] = b['avatar_url'];
  _db.update('users', allowed, where: (r) => r['email'] == email);
  return _json(200, {'message': 'Perfil atualizado'});
}

// ── CORS ──────────────────────────────────────────────────────────────────────

Middleware _cors() {
  const h = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
  return (handler) => (req) async {
        if (req.method == 'OPTIONS') return Response.ok('', headers: h);
        final res = await handler(req);
        return res.change(headers: h);
      };
}

// ── main ──────────────────────────────────────────────────────────────────────

void main() async {
  final router = Router()
    // ── Auth
    ..post('/register',        _register)
    ..post('/login',           _login)
    ..post('/forgot-password', _forgotPassword)
    ..post('/verify-code',     _verifyCode)
    ..post('/reset-password',  _resetPassword)
    // ── Perfil
    ..get('/profile',          _getProfile)
    ..put('/profile',          _updateProfile)
    // ── Favoritos
    ..get('/favorites',                _getFavorites)
    ..post('/favorites',               _addFavorite)
    ..delete('/favorites/<id>',        _removeFavorite)
    // ── Alertas de preço
    ..get('/price-alerts',             _getAlerts)
    ..post('/price-alerts',            _createAlert)
    ..delete('/price-alerts/<id>',     _deleteAlert)
    // ── Pedidos
    ..get('/orders',                   _getOrders)
    ..post('/orders',                  _createOrder)
    // ── Endereços
    ..get('/addresses',                _getAddresses)
    ..post('/addresses',               _createAddress)
    ..put('/addresses/<id>',           _updateAddress)
    ..delete('/addresses/<id>',        _deleteAddress)
    // ── Avaliações
    ..get('/products/<id>/reviews',    _getReviews)
    ..post('/reviews',                 _createReview)
    // ── Notificações
    ..get('/notifications',            _getNotifications)
    ..put('/notifications/<id>/read',  _markRead);

  final port    = int.parse(Platform.environment['PORT'] ?? '8090');
  final handler = Pipeline().addMiddleware(_cors()).addHandler(router.call);
  final server  = await serve(handler, InternetAddress.anyIPv4, port);

  stderr.writeln('');
  stderr.writeln('╔══════════════════════════════════════════╗');
  stderr.writeln('║  OlysTech Backend  •  porta ${server.port}         ║');
  stderr.writeln('╚══════════════════════════════════════════╝');
  stderr.writeln('Dados persistidos em: ${Directory('data').absolute.path}');
  stderr.writeln('');
  stderr.writeln('Tabelas (arquivos JSON):');
  stderr.writeln('  users · sessions · reset_tokens');
  stderr.writeln('  favorites · price_alerts');
  stderr.writeln('  orders · order_items');
  stderr.writeln('  addresses · reviews · notifications');
  stderr.writeln('');
}
