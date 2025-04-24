// secure-client.ts
import { performance } from 'perf_hooks';
import './wasm-exec.js'; // the Go runtime helper

// In Vercel Node 18+ you get global fetch, global TextEncoder/TextDecoder and
// the Web Crypto API out of the box, so all of those polyfills can be removed.

export interface GroundTruth {
  publicKeyFP: string;
  measurement: string;
}

export class SecureClient {
  private enclave: string;
  private repo: string;
  private static goInstance: any = null;
  private static initializationPromise: Promise<void> | null = null;

  constructor(enclave: string, repo: string) {
    this.enclave = enclave;
    this.repo = repo;
  }

  public static async initializeWasm(): Promise<void> {
    if (SecureClient.initializationPromise) {
      return SecureClient.initializationPromise;
    }

    SecureClient.initializationPromise = (async () => {
      SecureClient.goInstance = new (globalThis as any).Go();

      const resp = await fetch(
        'https://tinfoilsh.github.io/verifier-js/tinfoil-verifier.wasm'
      );
      if (!resp.ok) {
        throw new Error(`Failed to fetch WASM: ${resp.status}`);
      }
      const bytes = await resp.arrayBuffer();
      const { instance } = await WebAssembly.instantiate(
        bytes,
        (SecureClient.goInstance as any).importObject
      );
      // run() never resolves—so we don’t await it
      (SecureClient.goInstance as any).run(instance);

      // wait for the funcs to show up
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

    return SecureClient.initializationPromise;
  }

  public async initialize(): Promise<void> {
    await SecureClient.initializeWasm();
  }

  public async verify(): Promise<GroundTruth> {
    await this.initialize();

    if (
      typeof (globalThis as any).verifyCode !== 'function' ||
      typeof (globalThis as any).verifyEnclave !== 'function'
    ) {
      throw new Error('WASM functions not available');
    }

    const releaseRes = await fetch(
      `https://api.github.com/repos/${this.repo}/releases/latest`,
      {
        headers: {
          Accept: 'application/vnd.github.v3+json',
          'User-Agent': 'tinfoil-node-client',
        },
      }
    );
    if (!releaseRes.ok) {
      throw new Error(`GitHub API error: ${releaseRes.statusText}`);
    }
    const releaseData = await releaseRes.json();
    const eifMatch = releaseData.body?.match(/EIF hash: ([a-f0-9]{64})/i);
    const digMatch = releaseData.body?.match(/Digest: `([a-f0-9]{64})`/);
    const digest = eifMatch?.[1] || digMatch?.[1];
    if (!digest) {
      throw new Error('Digest not found in release notes');
    }

    const [meas, att] = await Promise.all([
      (globalThis as any).verifyCode(this.repo, digest),
      (globalThis as any).verifyEnclave(this.enclave),
    ]);

    if (meas !== att.measurement) {
      throw new Error('Measurement mismatch');
    }

    return {
      publicKeyFP: att.certificate,
      measurement: att.measurement,
    };
  }
}

// eager init
SecureClient.initializeWasm().catch((e) =>
  console.error('WASM init failed:', e)
);
