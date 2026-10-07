import { defineConfig } from "vocs/config";

export default defineConfig({
  title: "roxy",
  description:
    "A strict, programmable HTTP firewall: an egress proxy for untrusted workloads, or a gateway in front of the APIs your clients call.",
  // Pages live in docs/pages rather than the default src/pages.
  srcDir: ".",
  // GitHub Pages serves the site from /roxy-proxy/. Local dev overrides it.
  basePath: process.env.ROXY_DOCS_BASE ?? "/roxy-proxy",
  renderStrategy: "full-static",
  colorScheme: "light",
  // Deep teal; the rest of the palette is in pages/_root.css.
  accentColor: "#0f766e",
  banner: {
    content:
      "roxy is in early development. Expect frequent breaking changes to config, rules and interfaces.",
    variant: "warning",
    dismissable: false,
  },
  socials: [{ icon: "github", link: "https://github.com/roxy-proxy/roxy-proxy" }],
  editLink: {
    link: "https://github.com/roxy-proxy/roxy-proxy/edit/main/docs/pages/:path",
    text: "Edit on GitHub",
  },
  sidebar: [
    { text: "Overview", link: "/" },
    { text: "Quickstart", link: "/quickstart" },
    { text: "Principles and threat model", link: "/principles" },
    {
      text: "Configure policies",
      items: [
        { text: "How policies work", link: "/policies/overview" },
        { text: "Secrets", link: "/policies/secrets" },
        { text: "Rate limits and state", link: "/policies/rate-limits" },
        { text: "Body rules", link: "/policies/body-rules" },
        { text: "Address floor and lists", link: "/policies/address-lists" },
        { text: "WebSockets", link: "/policies/websockets" },
        { text: "Testing a policy", link: "/policies/testing" },
      ],
    },
    {
      text: "Addons",
      items: [
        { text: "Overview", link: "/addons/overview" },
        { text: "Configuring addons", link: "/addons/configuration" },
        { text: "Service layers", link: "/addons/service-layers" },
        { text: "Writing addons", link: "/addons/writing" },
        { text: "Host services", link: "/addons/host-services" },
        { text: "Safety", link: "/addons/safety" },
      ],
    },
    {
      text: "Deploy",
      items: [
        { text: "Sandbox containment", link: "/deploy/containment" },
        { text: "HTTP gateway", link: "/deploy/gateway" },
        { text: "Container image", link: "/deploy/docker" },
        { text: "Running without Docker", link: "/deploy/bare-metal" },
        { text: "Node mode", link: "/deploy/node-mode" },
      ],
    },
    {
      text: "Operate",
      items: [
        { text: "Operations", link: "/operate/operations" },
        { text: "Managing the CA", link: "/operate/ca-certificates" },
        { text: "Flow log and capture", link: "/operate/flow-log" },
      ],
    },
    {
      text: "Reference",
      items: [
        { text: "Configuration", link: "/reference/configuration" },
        { text: "Rule language", link: "/reference/rule-language" },
        { text: "HTTP", link: "/reference/http" },
        { text: "Upstream", link: "/reference/upstream" },
        { text: "TLS", link: "/reference/tls" },
        { text: "Resource limits", link: "/reference/limits" },
        { text: "Architecture", link: "/reference/architecture" },
        { text: "Node protocol", link: "/reference/node-protocol" },
        { text: "Development", link: "/reference/development" },
      ],
    },
  ],
});
