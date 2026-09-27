/**
 * Domain-holdout dataset loader — RRSI's "benchmark-disjoint" OOD check.
 *
 * The main search-quality fixture and the profile-tier / rerank-state cases
 * are all derived from known domains, so tuning on them risks overfitting the
 * parameters to exactly those domains' vocabulary. RRSI (arXiv:2609.24972)
 * guards against this by validating candidates on tasks the evolution never
 * saw; here that role is played by holding out one or more *domains* whose
 * cases are excluded from the evolve split entirely and only used to check
 * that a candidate that wins on evolve still generalizes to queries whose
 * tool vocabulary it was not tuned on.
 *
 * Implementation is deliberately shallow: it re-slices the search-quality
 * fixture by tag (each SearchEvalCase carries domain tags), so a caller that
 * already built the fixture gets an OOD slice for free. The dataset is
 * "disjoint" in the sense that its cases share no tags with the evolve set,
 * not that the fixtures are re-authored per run.
 */

import type { Tool } from '@modelcontextprotocol/server';
import type { SearchEvalCase } from '../../../tests/server/search/fixtures/search-quality.fixture';
import { buildSearchQualityFixture } from '../../../tests/server/search/fixtures/search-quality.fixture';

export interface LoadedDomainHoldoutDataset {
  readonly name: 'domain-holdout';
  /** Tags held out — every returned case carries one of these. */
  readonly heldOutTags: readonly string[];
  readonly tools: readonly Tool[];
  readonly domainOverrides: ReadonlyMap<string, string>;
  readonly cases: readonly SearchEvalCase[];
  /**
   * Tags that were requested but have no cases in the fixture. The dataset is
   * still usable without them, but the caller should know the request was
   * only partially honored — silently returning an empty OOD slice would
   * let tuning "pass" the OOD gate without ever testing it.
   */
  readonly unsatisfiedTags: readonly string[];
}

/**
 * Load an OOD holdout dataset: cases carrying any of `holdOutTags`, plus the
 * fixture's tool catalog (so the worker can build an engine over the same
 * tools the evolve slice used).
 *
 * When `holdOutTags` is empty this behaves as a full-slice selector: no tags
 * are held out, so every case lands in the OOD set. That is by design — a
 * caller that wants "everything as OOD" (a pure regression sweep) gets it for
 * free; a caller that partitions evolve vs OOD *by tag* passes explicit tags.
 */
export async function loadDomainHoldoutDataset(
  options: { holdOutTags?: readonly string[] } = {},
): Promise<LoadedDomainHoldoutDataset> {
  const fixture = buildSearchQualityFixture();
  const heldOutTags = options.holdOutTags ?? [];

  if (heldOutTags.length === 0) {
    // No tags requested → everything is OOD (pure sweep).
    return {
      name: 'domain-holdout',
      heldOutTags: [],
      tools: fixture.tools,
      domainOverrides: fixture.domainByToolName,
      cases: fixture.cases,
      unsatisfiedTags: [],
    };
  }

  const requested = new Set(heldOutTags);
  const cases = fixture.cases.filter((c) => c.tags.some((t) => requested.has(t)));
  const present = new Set<string>();
  for (const c of cases) for (const t of c.tags) if (requested.has(t)) present.add(t);
  const unsatisfiedTags = [...requested].filter((t) => !present.has(t));

  if (unsatisfiedTags.length > 0) {
    // Informational only — the slice is still usable with the satisfied tags.
    process.stderr.write(
      `[domain-holdout] requested tags without cases: ${unsatisfiedTags.join(', ')}\n`,
    );
  }

  return {
    name: 'domain-holdout',
    heldOutTags,
    tools: fixture.tools,
    domainOverrides: fixture.domainByToolName,
    cases,
    unsatisfiedTags,
  };
}
