import {Component} from '@angular/core';
import {
  adler32,
  argon2id,
  bcrypt, blake2b, blake2s, blake3, crc32, crc32c, createHMAC,
  createSHA256, keccak, md4, md5,
  pbkdf2,
  ripemd160, sha1, sha224, sha256, sha3, sha384, sha512,
  sm3,
  whirlpool, xxhash128,
  xxhash3,
  xxhash32,
  xxhash64
} from "hash-wasm";

const sha256Algo = createSHA256();

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent {
  title = 'dev-utils';
  ret: any = {};

  constructor() {

  }

  ngOnInit(): void {
    this.computeHash("apple").then(ret => {
      this.ret = ret;
    });
  }


  computeHMAC = async (input: string) => {

    const hasher = await createHMAC(sha256Algo, "apple");
    hasher.update(input);
    return hasher.digest();
  };
  computeHash = async (input: string) => {
    const ret: any = {};
    const salt = new Uint8Array(16);
    window.crypto.getRandomValues(salt);

    await Promise.all([
      (async () => (ret.adler32 = await adler32(input)))(),
      (async () => (ret.md4 = await md4(input)))(),
      (async () => (ret.md5 = await md5(input)))(),
      (async () => (ret.crc32 = await crc32(input)))(),
      (async () => (ret.crc32c = await crc32c(input)))(),
      (async () => (ret.blake2b = await blake2b(input, 256)))(),
      (async () => (ret.blake2s = await blake2s(input, 128)))(),
      (async () => (ret.blake3 = await blake3(input)))(),
      (async () => (ret.sha1 = await sha1(input)))(),
      (async () => (ret.sha224 = await sha224(input)))(),
      (async () => (ret.sha256 = await sha256(input)))(),
      (async () => (ret.sha384 = await sha384(input)))(),
      (async () => (ret.sha512 = await sha512(input)))(),
      (async () => (ret.sha3 = await sha3(input)))(),
      (async () => (ret.keccak = await keccak(input)))(),
      (async () => (ret.ripemd160 = await ripemd160(input)))(),
      (async () => (ret.xxhash32 = await xxhash32(input)))(),
      (async () => (ret.xxhash64 = await xxhash64(input)))(),
      (async () => (ret.xxhash3 = await xxhash3(input)))(),
      (async () => (ret.xxhash128 = await xxhash128(input)))(),
      (async () => (ret.sm3 = await sm3(input)))(),
      (async () => (ret.whirlpool = await whirlpool(input)))(),
      (async () => (ret.hmac = await this.computeHMAC(input)))(),
      (async () =>
        (ret.pbkdf2 = await pbkdf2({
          password: input,
          salt: "salt",
          iterations: 16,
          hashLength: 32,
          hashFunction: createSHA256()
        })))(),
      (async () =>
        input
          ? (ret.argon2id = await argon2id({
            password: input,
            salt,
            parallelism: 1,
            memorySize: 128,
            iterations: 4,
            hashLength: 16,
            outputType: "encoded"
          }))
          : "")(),
      (async () =>
        input && input.length < 72
          ? (ret.bcrypt = await bcrypt({
            password: input,
            salt,
            costFactor: 8,
            outputType: "encoded"
          }))
          : "")()
    ]);
    return ret;
  }
}
