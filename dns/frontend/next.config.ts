import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  async redirects() {
    return [
      {
        source: "/dns",
        destination: "/analytics/dns",
        permanent: true,
      },
      {
        source: "/threats",
        destination: "/analytics/threats",
        permanent: true,
      },
      {
        source: "/domains",
        destination: "/investigate/domains",
        permanent: true,
      },
      {
        source: "/domains/:domain",
        destination: "/investigate/domains/:domain",
        permanent: true,
      },
      {
        source: "/clients",
        destination: "/investigate/clients",
        permanent: true,
      },
      {
        source: "/clients/:clientIp",
        destination: "/investigate/clients/:clientIp",
        permanent: true,
      },
      {
        source: "/system",
        destination: "/settings",
        permanent: true,
      },
    ];
  },
  async rewrites() {
    const backendUrl = process.env.BACKEND_INTERNAL_URL || "http://127.0.0.1:8000";
    return [
      {
        source: "/api/v1/:path*",
        destination: `${backendUrl}/api/v1/:path*`,
      },
    ];
  },
};

export default nextConfig;
