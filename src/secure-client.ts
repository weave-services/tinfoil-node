// src/client.ts

import { performance } from 'perf_hooks';
import './wasm-exec.js';

// Use native fetch if present, otherwise fall back to node-fetch so Jest can mock it.
const fetchFn: typeof fetch =
  typeof globalThis.fetch === 'function'
    ? globalThis.fetch.bind(globalThis)
    : require('node-fetch').default;

export interface GroundTruth {
  publicKeyFP: string;
  measurement: string;
}

export class SecureClient {
  private enclave: string;
  private repo: string;
  private static goInstance: any = null;
  private static initPromise: Promise<void> | null = null;

  constructor(enclave: string, repo: string) {
    this.enclave = enclave;
    this.repo = repo;
  }

  // only kicks off once, on first verify()
  public static async initializeWasm(): Promise<void> {
    if (SecureClient.initPromise) {
      return SecureClient.initPromise;
    }
    SecureClient.initPromise = (async () => {
      SecureClient.goInstance = new (globalThis as any).Go();

      const resp = await fetchFn(
        'https://tinfoilsh.github.io/verifier-js/tinfoil-verifier.wasm'
      );
      if (!resp.ok) {
        throw new Error(`Failed to fetch WASM: ${resp.status}`);
      }
      const bytes = await resp.arrayBuffer();
      const { instance } = await WebAssembly.instantiate(
        bytes,
        SecureClient.goInstance.importObject
      );
      // Note: run() never resolves, and that’s fine
      SecureClient.goInstance.run(instance);

      // wait up to ~1s for the Go exports to appear
      for (let i = 0; i < 10; i++) {
        await new Promise((r) => setTimeout(r, 100));
        if (
          typeof (globalThis as any).verifyCode === 'function' &&
          typeof (globalThis as any).verifyEnclave === 'function'
        ) {
          return;
        }
      }
      throw new Error('WASM exports not ready');
    })();
    return SecureClient.initPromise;
  }

  public async verify(): Promise<GroundTruth> {
    await SecureClient.initializeWasm();

    // sanity check
    if (
      typeof (globalThis as any).verifyCode !== 'function' ||
      typeof (globalThis as any).verifyEnclave !== 'function'
    ) {
      throw new Error('WASM functions not available');
    }

    // fetch the latest release notes
    const releaseRes = await fetchFn(
      `https://api.github.com/repos/${this.repo}/releases/latest`,
      {
        headers: {
          Accept: 'application/vnd.github.v3+json',
          'User-Agent': 'tinfoil-node-client',
        },
      }
    );
    if (!releaseRes.ok) {
      throw new Error(
        `GitHub API error: ${releaseRes.status} ${releaseRes.statusText}`
      );
    }
    const releaseData = await releaseRes.json();
    const eifMatch = releaseData.body?.match(/EIF hash: ([a-f0-9]{64})/i);
    const digMatch = releaseData.body?.match(/Digest: `([a-f0-9]{64})`/);
    const digest = eifMatch?.[1] || digMatch?.[1];
    if (!digest) {
      throw new Error('Digest not found in release notes');
    }

    // call into the WASM exports
    const [measurement, attestation] = await Promise.all([
      (globalThis as any).verifyCode(this.repo, digest),
      (globalThis as any).verifyEnclave(this.enclave),
    ]);

    if (measurement !== attestation.measurement) {
      throw new Error('Measurement mismatch');
    }

    return {
      publicKeyFP: attestation.certificate,
      measurement: attestation.measurement,
    };
  }
}
