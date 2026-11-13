import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  allowedDevOrigins: ["192.168.29.153", "localhost"],
  async redirects() {
    return [{ source: "/signup", destination: "/login", permanent: false }]
  },
};

export default nextConfig;
