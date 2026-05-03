FROM dart:stable
WORKDIR /app
COPY pubspec.yaml pubspec.lock ./
RUN dart pub get --no-precompile
COPY . .
RUN dart compile exe bin/server.dart -o bin/server_bin
CMD ["/app/bin/server_bin"]
