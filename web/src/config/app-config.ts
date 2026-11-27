import packageJson from "../../package.json";

import { t } from "@/i18n";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "Goliath",
  version: packageJson.version,
  copyright: `© ${currentYear}, Goliath.`,
  meta: {
    title: t("Goliath — Autonomous Penetration Testing Console"),
    description: t("Console for the LLM-driven autonomous penetration testing system"),
  },
};
