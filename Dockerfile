FROM dart:stable
WORKDIR /app
COPY pubspec.yaml .
RUN dart pub get
COPY . .
RUN dart pub get --offline
CMD ["dart", "run", "bin/server.dart"]
