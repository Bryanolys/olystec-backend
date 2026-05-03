FROM dart:stable AS build
WORKDIR /app
COPY pubspec.yaml pubspec.lock* ./
RUN dart pub get
COPY . .
RUN dart compile exe bin/server.dart -o bin/server_bin

FROM debian:bullseye-slim
WORKDIR /app
COPY --from=build /app/bin/server_bin /app/bin/server_bin
CMD ["/app/bin/server_bin"]
