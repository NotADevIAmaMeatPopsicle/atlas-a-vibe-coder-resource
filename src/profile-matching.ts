import type { ResolvedProfile } from './types.js';
import { matchesGlob } from './util/paths.js';

export function isExpectedFixtureUnresolvedImport(
  profile: ResolvedProfile,
  fromPath: string,
  specifier: string
): boolean {
  return (profile.fixtureUnresolvedImports ?? []).some((expectation) => (
    expectation.specifier === specifier && matchesGlob(fromPath, expectation.sourcePattern)
  ));
}
