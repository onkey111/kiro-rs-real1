# ============================================
# Stage 1: Build - Biên dịch ứng dụng Rust
# ============================================
FROM rust:1.83-slim-bookworm AS builder

# Cài đặt các dependencies cần thiết cho build
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy toàn bộ source code
COPY . .

# Build release binary
RUN cargo build --release

# ============================================
# Stage 2: Runtime - Image chạy ứng dụng
# ============================================
FROM debian:bookworm-slim

# Cài đặt runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary từ builder stage
COPY --from=builder /app/target/release/kiro-rs /app/kiro-rs

# Copy các file config mẫu (người dùng sẽ mount config thực tế)
COPY config.example.json /app/config.example.json

# Tạo thư mục data để mount volume
RUN mkdir -p /app/data

# Expose port mặc định
EXPOSE 8990

# Biến môi trường cho logging
ENV RUST_LOG=info

# Chạy ứng dụng với config từ /app/data
CMD ["/app/kiro-rs", "-c", "/app/data/config.json", "--credentials", "/app/data/credentials.json"]

