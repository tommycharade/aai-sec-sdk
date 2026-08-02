#!/usr/bin/env node
import * as cdk from "aws-cdk-lib";
import { RegionalTransitionJournalStack } from "../lib/regional-transition-journal-stack";

const app = new cdk.App();
new RegionalTransitionJournalStack(app, "AaiSecRegionalTransitionJournal", {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.TRANSITION_COORDINATION_REGION,
  },
  primaryRegion: process.env.PRIMARY_REGION ?? "",
  recoveryRegion: process.env.RECOVERY_REGION ?? "",
  tableName: process.env.TRANSITION_JOURNAL_TABLE_NAME ?? "",
  description: "Independent single-writer authority for regional transition compare-and-swap",
  tags: {
    ActiveAuthority: "transition-only",
    CoordinationModel: "single-region-strong-cas",
  },
});
