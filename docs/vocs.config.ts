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
    {
      text: "Start",
      items: [
        { text: "Overview", link: "/" },
        { text: "Quickstart", link: "/quickstart" },
      ],
    },
    {
      text: "Guides",
      items: [
        { text: "Sandbox containment", link: "/guides/containment" },
        { text: "HTTP gateway", link: "/guides/gateway" },
        { text: "Run roxy", link: "/guides/run" },
        { text: "Node mode", link: "/guides/node-mode" },
        { text: "Operations", link: "/guides/operations" },
        { text: "Managing the CA", link: "/guides/ca-certificates" },
        { text: "Testing a policy", link: "/guides/testing-a-policy" },
        { text: "Writing addons", link: "/guides/writing-addons" },
      ],
    },
    {
      text: "Design",
      items: [
        { text: "How roxy works", link: "/design/how-it-works" },
        { text: "Threat model and guarantees", link: "/design/threat-model" },
        { text: "Policy evaluation", link: "/design/policy-evaluation" },
        { text: "Addon model", link: "/design/addon-model" },
        { text: "Performance", link: "/design/performance" },
      ],
    },
    {
      text: "Reference",
      items: [
        { text: "Configuration", link: "/reference/configuration" },
        { text: "Rule language", link: "/reference/rule-language" },
        { text: "Secrets", link: "/reference/secrets" },
        { text: "Rate limits and state", link: "/reference/rate-limits" },
        { text: "Address floor and lists", link: "/reference/address-lists" },
        { text: "WebSockets", link: "/reference/websockets" },
        { text: "HTTP", link: "/reference/http" },
        { text: "Upstream", link: "/reference/upstream" },
        { text: "TLS", link: "/reference/tls" },
        { text: "Resource limits", link: "/reference/limits" },
        { text: "Addon configuration", link: "/reference/addon-configuration" },
        { text: "Service layer protocol", link: "/reference/service-layers" },
        { text: "Host services", link: "/reference/host-services" },
        { text: "Flow log and capture", link: "/reference/flow-log" },
        { text: "Node protocol", link: "/reference/node-protocol" },
        { text: "Architecture", link: "/reference/architecture" },
        { text: "Development", link: "/reference/development" },
      ],
    },
  ],
});
