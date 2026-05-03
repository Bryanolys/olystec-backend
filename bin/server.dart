import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart';
import 'package:shelf_router/shelf_router.dart';
import 'package:crypto/crypto.dart';
import 'package:postgres/postgres.dart';

// ── Database ──────────────────────────────────────────────────────────────────

late Connection _db;

Future<void> _initDb() async {
  final url = Platform.environment['DATABASE_URL'];
  if (url == null) throw Exception('DATABASE_URL não definido');

  _db = await Connection.open(
    Endpoint.parse(url),
    settings: ConnectionSettings(sslMode: SslMode.require),
  );

  await _db.execute('''
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      phone TEXT,
      avatar_url TEXT,
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ
    )
  ''');

  await _db.execute('''
    CREATE TABLE IF NOT EXISTS sessions (
      id SERIAL PRIMARY KEY,
      user_id INT NOT NULL,
      email TEXT NOT NULL,
      ip TEXT,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  ''');

  await _db.execute('''
    CREATE TABLE IF NOT EXISTS reset_tokens (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL,
      code TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  ''');

  await _db.execute('''
    CREATE TABLE IF NOT EXISTS favorites (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL,
      product_id TEXT NOT NULL,
      product_name TEXT,
      price DOUBLE PRECISION,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(email, product_id)
    )
  ''');

  await _db.execute('''
    CREATE TABLE IF NOT EXISTS price_alerts (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL,
      product_id TEXT NOT NULL,
      product_name TEXT,
      current_price DOUBLE PRECISION,
      target_price DOUBLE PRECISION NOT NULL,
      active BOOLEAN DEFAULT TRUE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  ''');

  await _db.execute('''
    CREATE TABLE IF NOT EXISTS orders (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL,
      total DOUBLE PRECISION NOT NULL,
      status TEXT DEFAULT 'pending',
      address_id INT,
      payment_method TEXT DEFAULT 'credit_card',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ
    )
  ''');

  await _db.execute('''
    CREATE TABLE IF NOT EXISTS order_items (
      id SERIAL PRIMARY KEY,
      order_id INT NOT NULL,
      product_id TEXT NOT NULL,
      product_name TEXT,
      store TEXT,
      price DOUBLE PRECISION NOT NULL,
      quantity INT DEFAULT 1,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  ''');

  await _db.execute('''
    CREATE TABLE IF NOT EXISTS addresses (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL,
      label TEXT DEFAULT 'Casa',
      recipient TEXT,
      street TEXT,
      number TEXT,
      complement TEXT,
      neighborhood TEXT,
      city TEXT,
      state TEXT,
      zip_code TEXT,
      is_default BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ
    )
  ''');

  await _db.execute('''
    CREATE TABLE IF NOT EXISTS reviews (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL,
      product_id TEXT NOT NULL,
      rating INT NOT NULL CHECK (rating BETWEEN 1 AND 5),
      comment TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW(),
      UNIQUE(email, product_id)
    )
  ''');

  await _db.execute('''
    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      email TEXT NOT NULL,
      type TEXT,
      title TEXT,
      body TEXT,
      read BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  ''');
}

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

Map<String, dynamic> _rowToMap(ResultRow row) {
  final map = <String, dynamic>{};
  for (final col in row.schema.columns) {
    final val = row[col.columnName];
    if (val is DateTime) {
      map[col.columnName!] = val.toUtc().toIso8601String();
    } else {
      map[col.columnName!] = val;
    }
  }
  return map;
}

// ── Auth: /register ───────────────────────────────────────────────────────────

Future<Response> _register(Request req) async {
  final b = await _parseBody(req);
  if (b == null) return _json(400, {'message': 'JSON inválido'});

  final name  = (b['name']    as String?)?.trim();
  final email = (b['email']   as String?)?.trim().toLowerCase();
  final pass  = b['password'] as String?;

  if ([name, email, pass].any((v) => v == null || v!.isEmpty)) {
    return _json(400, {'message': 'Preencha todos os campos'});
  }
  if (!email!.contains('@')) {
    return _json(400, {'message': 'Informe um e-mail válido'});
  }

  try {
    final exists = await _db.execute(
      Sql.named('SELECT id FROM users WHERE email = @email'),
      parameters: {'email': email},
    );
    if (exists.isNotEmpty) {
      return _json(409, {'message': 'Este e-mail já está cadastrado'});
    }

    await _db.execute(
      Sql.named(
          'INSERT INTO users (name, email, password_hash) VALUES (@name, @email, @hash)'),
      parameters: {'name': name, 'email': email, 'hash': _hash(pass!)},
    );

    await _db.execute(
      Sql.named('''INSERT INTO notifications (email, type, title, body)
          VALUES (@email, @type, @title, @body)'''),
      parameters: {
        'email': email,
        'type': 'welcome',
        'title': 'Bem-vindo à OlysTech! 🎉',
        'body': 'Sua conta foi criada com sucesso. Explore as melhores ofertas!',
      },
    );

    return _json(201, {
      'message': 'Cadastro realizado com sucesso',
      'user': {'name': name, 'email': email},
    });
  } catch (e) {
    return _json(500, {'message': 'Erro interno: $e'});
  }
}

// ── Auth: /login ──────────────────────────────────────────────────────────────

Future<Response> _login(Request req) async {
  final b = await _parseBody(req);
  if (b == null) return _json(400, {'message': 'JSON inválido'});

  final email = (b['email']   as String?)?.trim().toLowerCase();
  final pass  = b['password'] as String?;

  if ([email, pass].any((v) => v == null || v!.isEmpty)) {
    return _json(400, {'message': 'Preencha todos os campos'});
  }

  try {
    final rows = await _db.execute(
      Sql.named('SELECT * FROM users WHERE email = @email AND password_hash = @hash AND active = TRUE'),
      parameters: {'email': email, 'hash': _hash(pass!)},
    );

    if (rows.isEmpty) {
      return _json(401, {'message': 'E-mail ou senha incorretos'});
    }

    final user = _rowToMap(rows.first);
    await _db.execute(
      Sql.named('INSERT INTO sessions (user_id, email, ip) VALUES (@uid, @email, @ip)'),
      parameters: {
        'uid': user['id'],
        'email': email,
        'ip': req.headers['x-forwarded-for'] ?? 'local',
      },
    );

    return _json(200, {
      'user': {'name': user['name'], 'email': user['email']},
    });
  } catch (e) {
    return _json(500, {'message': 'Erro interno: $e'});
  }
}

// ── Auth: /forgot-password ────────────────────────────────────────────────────

Future<Response> _forgotPassword(Request req) async {
  final b = await _parseBody(req);
  if (b == null) return _json(400, {'message': 'JSON inválido'});

  final email = (b['email'] as String?)?.trim().toLowerCase();
  if (email == null || !email.contains('@')) {
    return _json(400, {'message': 'Informe um e-mail válido.'});
  }

  final exists = await _db.execute(
    Sql.named('SELECT id FROM users WHERE email = @email'),
    parameters: {'email': email},
  );
  if (exists.isEmpty) {
    return _json(200, {'message': 'Se este e-mail estiver cadastrado, você receberá o código.'});
  }

  final code      = _otp();
  final expiresAt = DateTime.now().toUtc().add(const Duration(minutes: 15));

  await _db.execute(
    Sql.named('DELETE FROM reset_tokens WHERE email = @email'),
    parameters: {'email': email},
  );
  await _db.execute(
    Sql.named('INSERT INTO reset_tokens (email, code, expires_at) VALUES (@email, @code, @exp)'),
    parameters: {'email': email, 'code': code, 'exp': expiresAt},
  );

  stderr.writeln('[DEV] Código para $email: $code');
  return _json(200, {'message': 'Código enviado.', 'dev_code': code});
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

  final rows = await _db.execute(
    Sql.named('SELECT * FROM reset_tokens WHERE email = @email AND code = @code'),
    parameters: {'email': email, 'code': code},
  );
  if (rows.isEmpty) return _json(400, {'message': 'Código inválido ou expirado.'});

  final token = _rowToMap(rows.first);
  final exp   = DateTime.parse(token['expires_at'] as String);
  if (DateTime.now().toUtc().isAfter(exp)) {
    await _db.execute(
      Sql.named('DELETE FROM reset_tokens WHERE email = @email'),
      parameters: {'email': email},
    );
    return _json(400, {'message': 'Código expirado. Solicite um novo.'});
  }

  return _json(200, {'message': 'Código válido.'});
}

// ── Auth: /reset-password ─────────────────────────────────────────────────────

Future<Response> _resetPassword(Request req) async {
  final b = await _parseBody(req);
  if (b == null) return _json(400, {'message': 'JSON inválido'});

  final email = (b['email']   as String?)?.trim().toLowerCase();
  final code  = (b['code']    as String?)?.trim();
  final pass  = b['password'] as String?;

  if (email == null || code == null || code.length != 6 ||
      pass == null || pass.length < 6) {
    return _json(400, {'message': 'Dados inválidos.'});
  }

  final rows = await _db.execute(
    Sql.named('SELECT * FROM reset_tokens WHERE email = @email AND code = @code'),
    parameters: {'email': email, 'code': code},
  );
  if (rows.isEmpty) return _json(400, {'message': 'Código inválido ou expirado.'});

  final token = _rowToMap(rows.first);
  final exp   = DateTime.parse(token['expires_at'] as String);
  if (DateTime.now().toUtc().isAfter(exp)) {
    await _db.execute(
      Sql.named('DELETE FROM reset_tokens WHERE email = @email'),
      parameters: {'email': email},
    );
    return _json(400, {'message': 'Código expirado.'});
  }

  await _db.execute(
    Sql.named('UPDATE users SET password_hash = @hash, updated_at = NOW() WHERE email = @email'),
    parameters: {'hash': _hash(pass), 'email': email},
  );
  await _db.execute(
    Sql.named('DELETE FROM reset_tokens WHERE email = @email'),
    parameters: {'email': email},
  );

  return _json(200, {'message': 'Senha redefinida com sucesso.'});
}

// ── Perfil ────────────────────────────────────────────────────────────────────

Future<Response> _getProfile(Request req) async {
  final email = req.url.queryParameters['email'];
  if (email == null || email.isEmpty) return _json(400, {'message': 'E-mail obrigatório'});

  final rows = await _db.execute(
    Sql.named('SELECT id, name, email, phone, avatar_url, created_at FROM users WHERE email = @email'),
    parameters: {'email': email},
  );
  if (rows.isEmpty) return _json(404, {'message': 'Usuário não encontrado'});

  return _json(200, {'user': _rowToMap(rows.first)});
}

Future<Response> _updateProfile(Request req) async {
  final b = await _parseBody(req);
  if (b == null) return _json(400, {'message': 'JSON inválido'});
  final email = (b['email'] as String?)?.trim().toLowerCase();
  if (email == null || email.isEmpty) return _json(400, {'message': 'E-mail obrigatório'});

  if (b['name'] != null) {
    await _db.execute(
      Sql.named('UPDATE users SET name = @name, updated_at = NOW() WHERE email = @email'),
      parameters: {'name': (b['name'] as String).trim(), 'email': email},
    );
  }
  if (b['phone'] != null) {
    await _db.execute(
      Sql.named('UPDATE users SET phone = @phone, updated_at = NOW() WHERE email = @email'),
      parameters: {'phone': b['phone'], 'email': email},
    );
  }
  if (b['avatar_url'] != null) {
    await _db.execute(
      Sql.named('UPDATE users SET avatar_url = @url, updated_at = NOW() WHERE email = @email'),
      parameters: {'url': b['avatar_url'], 'email': email},
    );
  }

  return _json(200, {'message': 'Perfil atualizado'});
}

// ── Favoritos ─────────────────────────────────────────────────────────────────

Future<Response> _getFavorites(Request req) async {
  final email = req.url.queryParameters['email'];
  if (email == null || email.isEmpty) return _json(400, {'message': 'E-mail obrigatório'});

  final rows = await _db.execute(
    Sql.named('SELECT * FROM favorites WHERE email = @email ORDER BY created_at DESC'),
    parameters: {'email': email},
  );
  return _json(200, {'favorites': rows.map(_rowToMap).toList()});
}

Future<Response> _addFavorite(Request req) async {
  final b = await _parseBody(req);
  if (b == null) return _json(400, {'message': 'JSON inválido'});

  final email     = (b['email']     as String?)?.trim().toLowerCase();
  final productId = b['product_id'] as String?;
  if (email == null || productId == null) return _json(400, {'message': 'Dados inválidos'});

  await _db.execute(
    Sql.named('''INSERT INTO favorites (email, product_id, product_name, price)
        VALUES (@email, @pid, @name, @price)
        ON CONFLICT (email, product_id) DO NOTHING'''),
    parameters: {
      'email': email,
      'pid': productId,
      'name': b['product_name'] ?? '',
      'price': (b['price'] as num?)?.toDouble(),
    },
  );
  return _json(201, {'message': 'Adicionado aos favoritos'});
}

Future<Response> _removeFavorite(Request req, String productId) async {
  final email = req.url.queryParameters['email'];
  if (email == null || email.isEmpty) return _json(400, {'message': 'E-mail obrigatório'});

  await _db.execute(
    Sql.named('DELETE FROM favorites WHERE email = @email AND product_id = @pid'),
    parameters: {'email': email, 'pid': productId},
  );
  return _json(200, {'message': 'Removido dos favoritos'});
}

// ── Alertas de Preço ──────────────────────────────────────────────────────────

Future<Response> _getAlerts(Request req) async {
  final email = req.url.queryParameters['email'];
  if (email == null || email.isEmpty) return _json(400, {'message': 'E-mail obrigatório'});

  final rows = await _db.execute(
    Sql.named('SELECT * FROM price_alerts WHERE email = @email ORDER BY created_at DESC'),
    parameters: {'email': email},
  );
  return _json(200, {'alerts': rows.map(_rowToMap).toList()});
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

  final rows = await _db.execute(
    Sql.named('''INSERT INTO price_alerts (email, product_id, product_name, current_price, target_price)
        VALUES (@email, @pid, @name, @cur, @tgt) RETURNING *'''),
    parameters: {
      'email': email,
      'pid': productId,
      'name': b['product_name'] ?? '',
      'cur': (b['current_price'] as num?)?.toDouble(),
      'tgt': targetPrice,
    },
  );
  return _json(201, {'alert': _rowToMap(rows.first)});
}

Future<Response> _deleteAlert(Request req, String id) async {
  final idInt = int.tryParse(id);
  if (idInt == null) return _json(400, {'message': 'ID inválido'});
  await _db.execute(
    Sql.named('DELETE FROM price_alerts WHERE id = @id'),
    parameters: {'id': idInt},
  );
  return _json(200, {'message': 'Alerta removido'});
}

// ── Pedidos ───────────────────────────────────────────────────────────────────

Future<Response> _getOrders(Request req) async {
  final email = req.url.queryParameters['email'];
  if (email == null || email.isEmpty) return _json(400, {'message': 'E-mail obrigatório'});

  final orders = await _db.execute(
    Sql.named('SELECT * FROM orders WHERE email = @email ORDER BY created_at DESC'),
    parameters: {'email': email},
  );

  final result = <Map<String, dynamic>>[];
  for (final o in orders) {
    final order = _rowToMap(o);
    final items = await _db.execute(
      Sql.named('SELECT * FROM order_items WHERE order_id = @oid'),
      parameters: {'oid': order['id']},
    );
    result.add({...order, 'items': items.map(_rowToMap).toList()});
  }
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

  final orderRows = await _db.execute(
    Sql.named('''INSERT INTO orders (email, total, address_id, payment_method)
        VALUES (@email, @total, @addr, @pay) RETURNING *'''),
    parameters: {
      'email': email,
      'total': total,
      'addr': b['address_id'],
      'pay': b['payment_method'] ?? 'credit_card',
    },
  );
  final order = _rowToMap(orderRows.first);

  for (final raw in items) {
    final item = raw as Map<String, dynamic>;
    await _db.execute(
      Sql.named('''INSERT INTO order_items (order_id, product_id, product_name, store, price, quantity)
          VALUES (@oid, @pid, @name, @store, @price, @qty)'''),
      parameters: {
        'oid': order['id'],
        'pid': '${item['product_id']}',
        'name': item['product_name'] ?? '',
        'store': item['store'] ?? '',
        'price': (item['price'] as num?)?.toDouble() ?? 0.0,
        'qty': (item['quantity'] as num?)?.toInt() ?? 1,
      },
    );
  }

  await _db.execute(
    Sql.named('''INSERT INTO notifications (email, type, title, body)
        VALUES (@email, @type, @title, @body)'''),
    parameters: {
      'email': email,
      'type': 'order',
      'title': 'Pedido #${order['id']} confirmado!',
      'body': 'Seu pedido de R\$ ${total.toStringAsFixed(2)} foi realizado com sucesso.',
    },
  );

  return _json(201, {'order': order});
}

// ── Endereços ─────────────────────────────────────────────────────────────────

Future<Response> _getAddresses(Request req) async {
  final email = req.url.queryParameters['email'];
  if (email == null || email.isEmpty) return _json(400, {'message': 'E-mail obrigatório'});

  final rows = await _db.execute(
    Sql.named('SELECT * FROM addresses WHERE email = @email ORDER BY is_default DESC, created_at'),
    parameters: {'email': email},
  );
  return _json(200, {'addresses': rows.map(_rowToMap).toList()});
}

Future<Response> _createAddress(Request req) async {
  final b = await _parseBody(req);
  if (b == null) return _json(400, {'message': 'JSON inválido'});

  final email = (b['email'] as String?)?.trim().toLowerCase();
  if (email == null || email.isEmpty) return _json(400, {'message': 'E-mail obrigatório'});

  if (b['is_default'] == true) {
    await _db.execute(
      Sql.named('UPDATE addresses SET is_default = FALSE WHERE email = @email'),
      parameters: {'email': email},
    );
  }

  final rows = await _db.execute(
    Sql.named('''INSERT INTO addresses
        (email, label, recipient, street, number, complement, neighborhood, city, state, zip_code, is_default)
        VALUES (@email, @label, @recip, @street, @num, @comp, @neigh, @city, @state, @zip, @def)
        RETURNING *'''),
    parameters: {
      'email': email,
      'label': b['label'] ?? 'Casa',
      'recip': b['recipient'] ?? '',
      'street': b['street'] ?? '',
      'num': b['number'] ?? '',
      'comp': b['complement'] ?? '',
      'neigh': b['neighborhood'] ?? '',
      'city': b['city'] ?? '',
      'state': b['state'] ?? '',
      'zip': b['zip_code'] ?? '',
      'def': b['is_default'] ?? false,
    },
  );
  return _json(201, {'address': _rowToMap(rows.first)});
}

Future<Response> _updateAddress(Request req, String id) async {
  final b = await _parseBody(req);
  if (b == null) return _json(400, {'message': 'JSON inválido'});
  final idInt = int.tryParse(id);
  if (idInt == null) return _json(400, {'message': 'ID inválido'});

  final fields = <String>[];
  final params = <String, dynamic>{'id': idInt};
  void set(String col, String key) {
    if (b[key] != null) { fields.add('$col = @$key'); params[key] = b[key]; }
  }
  set('label', 'label'); set('recipient', 'recipient');
  set('street', 'street'); set('number', 'number');
  set('complement', 'complement'); set('neighborhood', 'neighborhood');
  set('city', 'city'); set('state', 'state');
  set('zip_code', 'zip_code'); set('is_default', 'is_default');

  if (fields.isEmpty) return _json(200, {'message': 'Nada a atualizar'});
  fields.add('updated_at = NOW()');

  await _db.execute(
    Sql.named('UPDATE addresses SET ${fields.join(', ')} WHERE id = @id'),
    parameters: params,
  );
  return _json(200, {'message': 'Endereço atualizado'});
}

Future<Response> _deleteAddress(Request req, String id) async {
  final idInt = int.tryParse(id);
  if (idInt == null) return _json(400, {'message': 'ID inválido'});
  await _db.execute(
    Sql.named('DELETE FROM addresses WHERE id = @id'),
    parameters: {'id': idInt},
  );
  return _json(200, {'message': 'Endereço removido'});
}

// ── Avaliações ────────────────────────────────────────────────────────────────

Future<Response> _getReviews(Request req, String productId) async {
  final rows = await _db.execute(
    Sql.named('SELECT * FROM reviews WHERE product_id = @pid ORDER BY created_at DESC'),
    parameters: {'pid': productId},
  );
  final list = rows.map(_rowToMap).toList();
  final avg  = list.isEmpty
      ? 0.0
      : list.map((r) => (r['rating'] as num).toDouble()).reduce((a, b) => a + b) /
          list.length;
  return _json(200, {
    'reviews': list,
    'average': double.parse(avg.toStringAsFixed(1)),
    'count': list.length,
  });
}

Future<Response> _createReview(Request req) async {
  final b = await _parseBody(req);
  if (b == null) return _json(400, {'message': 'JSON inválido'});

  final email     = (b['email']     as String?)?.trim().toLowerCase();
  final productId = b['product_id'] as String?;
  final rating    = (b['rating']    as num?)?.toInt();
  if (email == null || productId == null || rating == null ||
      rating < 1 || rating > 5) {
    return _json(400, {'message': 'Dados inválidos (nota entre 1 e 5)'});
  }

  final rows = await _db.execute(
    Sql.named('''INSERT INTO reviews (email, product_id, rating, comment)
        VALUES (@email, @pid, @rating, @comment)
        ON CONFLICT (email, product_id) DO UPDATE
          SET rating = EXCLUDED.rating, comment = EXCLUDED.comment
        RETURNING *'''),
    parameters: {
      'email': email,
      'pid': productId,
      'rating': rating,
      'comment': (b['comment'] as String?)?.trim() ?? '',
    },
  );
  return _json(201, {'review': _rowToMap(rows.first)});
}

// ── Notificações ──────────────────────────────────────────────────────────────

Future<Response> _getNotifications(Request req) async {
  final email = req.url.queryParameters['email'];
  if (email == null || email.isEmpty) return _json(400, {'message': 'E-mail obrigatório'});

  final rows = await _db.execute(
    Sql.named('SELECT * FROM notifications WHERE email = @email ORDER BY created_at DESC'),
    parameters: {'email': email},
  );
  return _json(200, {'notifications': rows.map(_rowToMap).toList()});
}

Future<Response> _markRead(Request req, String id) async {
  final idInt = int.tryParse(id);
  if (idInt == null) return _json(400, {'message': 'ID inválido'});
  await _db.execute(
    Sql.named('UPDATE notifications SET read = TRUE WHERE id = @id'),
    parameters: {'id': idInt},
  );
  return _json(200, {'message': 'Notificação marcada como lida'});
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
  await _initDb();

  final router = Router()
    ..get('/',       (_) => _json(200, {'status': 'ok', 'service': 'OlysTech API'}))
    ..get('/health', (_) => _json(200, {'status': 'ok'}))
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
    ..get('/favorites',               _getFavorites)
    ..post('/favorites',              _addFavorite)
    ..delete('/favorites/<id>',       _removeFavorite)
    // ── Alertas de preço
    ..get('/price-alerts',            _getAlerts)
    ..post('/price-alerts',           _createAlert)
    ..delete('/price-alerts/<id>',    _deleteAlert)
    // ── Pedidos
    ..get('/orders',                  _getOrders)
    ..post('/orders',                 _createOrder)
    // ── Endereços
    ..get('/addresses',               _getAddresses)
    ..post('/addresses',              _createAddress)
    ..put('/addresses/<id>',          _updateAddress)
    ..delete('/addresses/<id>',       _deleteAddress)
    // ── Avaliações
    ..get('/products/<id>/reviews',   _getReviews)
    ..post('/reviews',                _createReview)
    // ── Notificações
    ..get('/notifications',           _getNotifications)
    ..put('/notifications/<id>/read', _markRead);

  final port    = int.parse(Platform.environment['PORT'] ?? '8090');
  final handler = Pipeline().addMiddleware(_cors()).addHandler(router.call);
  final server  = await serve(handler, InternetAddress.anyIPv4, port);

  stderr.writeln('OlysTech Backend rodando na porta ${server.port}');
}
