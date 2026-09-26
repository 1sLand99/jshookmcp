/**
 * Choose the instrumentation implementation from config.
 *
 * Kept out of `InstrumentationContract.ts` so the contract module stays free of
 * config types, and out of `MCPServer` so the decision is testable on its own.
 *
 * The default is `NoopInstrumentation`: a library should not pay for telemetry
 * the embedder did not ask for, and the contract explicitly allows a no-op.
 * `observability.exporter: 'memory'` opts into `InMemoryInstrumentation`, which
 * is bounded and inspectable from inside the process — the option that makes
 * "is the instrumentation actually working?" answerable.
 *
 * The switch is real: it selects a different object with different behaviour.
 * A config key that changes nothing would be its own instance of the defect
 * class this work exists to remove.
 *
 * SCOPE CAVEAT, read before assuming telemetry is live: the shipped
 * `getConfig()` has no `observability` key, so from a real `Config` this always
 * sees `undefined` and always returns `NoopInstrumentation`. It only selects the
 * memory buffer for a programmatically-constructed `Config` (tests, embedders).
 * See the `Config.observability` doc comment in `src/types/config.ts` for what
 * is still needed to make it operator-reachable.
 */

import type { Config } from '@internal-types/index';
import { InMemoryInstrumentation } from './InMemoryInstrumentation';
import { type InstrumentationContract, NoopInstrumentation } from './InstrumentationContract';

export function createInstrumentation(
  config: Pick<Config, 'observability'>,
): InstrumentationContract {
  const settings = config.observability;
  if (settings?.exporter === 'memory') {
    return new InMemoryInstrumentation(settings.maxSpans);
  }
  return new NoopInstrumentation();
}
