import { defineConfig } from "vocs";

// Light only. One accent, a deep teal, with neutral greys around it.
const accent = "#0f766e";
const accentHover = "#115e59";

export default defineConfig({
  title: "roxy",
  description: "A strict, programmable HTTP firewall and egress proxy.",
  rootDir: ".",
  aiCta: false,
  // GitHub Pages serves the site from /roxy-proxy/. Local dev overrides it.
  basePath: process.env.ROXY_DOCS_BASE ?? "/roxy-proxy",
  font: {
    google: "Inter",
    mono: { google: "JetBrains Mono" },
  },
  socials: [{ icon: "github", link: "https://github.com/roxy-proxy/roxy-proxy" }],
  editLink: {
    pattern: "https://github.com/roxy-proxy/roxy-proxy/edit/main/docs/pages/:path",
    text: "Edit on GitHub",
  },
  theme: {
    colorScheme: "light",
    accentColor: accent,
    variables: {
      color: {
        background: "#ffffff",
        background2: "#f8f9f8",
        background3: "#f3f5f4",
        background4: "#eceeed",
        background5: "#e3e6e5",
        backgroundDark: "#f8f9f8",
        backgroundAccent: accent,
        backgroundAccentHover: accentHover,
        backgroundAccentText: "#ffffff",
        border: "#e6e8e7",
        border2: "#cfd4d2",
        borderAccent: accent,
        heading: "#16201e",
        text: "#3d4846",
        text2: "#5f6b68",
        text3: "#7e8986",
        text4: "#b6bdbb",
        textAccent: accent,
        textAccentHover: accentHover,
        link: accent,
        linkHover: accentHover,
        codeBlockBackground: "#f8f9f8",
        codeInlineBackground: "#f1f4f3",
        codeInlineBorder: "#e3e6e5",
        codeInlineText: "#16201e",
        codeTitleBackground: "#f1f4f3",
        infoBackground: "#0f766e0f",
        infoBorder: "#0f766e40",
        infoText: accentHover,
        tableBorder: "#e6e8e7",
        tableHeaderBackground: "#f3f5f4",
        tableHeaderText: "#16201e",
        hr: "#e6e8e7",
      },
    },
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
        { text: "Containing a workload", link: "/deploy/overview" },
        { text: "Container image", link: "/deploy/docker" },
        { text: "Running without Docker", link: "/deploy/bare-metal" },
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
        { text: "Development", link: "/reference/development" },
      ],
    },
  ],
});
