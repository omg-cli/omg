import type { RpcStub } from "capnweb";

interface Api {
  mutable(value: [string, number]): void;
  readonly(value: readonly [string, number]): void;
  optional(value: [string, number?]): void;
  variadic(value: [string, ...number[]]): void;
  readonlyVariadic(value: readonly [string, ...number[]]): void;
  promise(value: [Promise<string>, number]): void;
}

type Assert<T extends true> = T;

type Reject<T extends false> = T;

type Fits<Value, Target> = [Value] extends [Target] ? true : false;

type Argument<Name extends keyof Api> = Parameters<RpcStub<Api>[Name]>[0];

export type MutableAcceptsResolved = Assert<Fits<[string, number], Argument<"mutable">>>;

export type MutableAcceptsPromises = Assert<
  Fits<[Promise<string>, Promise<number>], Argument<"mutable">>
>;

export type MutableAcceptsWholePromise = Assert<
  Fits<Promise<[string, number]>, Argument<"mutable">>
>;

export type MutableRejectsWrongSlot = Reject<
  Fits<[Promise<number>, Promise<string>], Argument<"mutable">>
>;

export type MutableRejectsMissing = Reject<Fits<[Promise<string>], Argument<"mutable">>>;

export type MutableRejectsExtra = Reject<
  Fits<[Promise<string>, Promise<number>, Promise<number>], Argument<"mutable">>
>;

export type ReadonlyAcceptsPromises = Assert<
  Fits<readonly [Promise<string>, Promise<number>], Argument<"readonly">>
>;

export type ReadonlyRejectsWrongSlot = Reject<
  Fits<readonly [Promise<number>, Promise<string>], Argument<"readonly">>
>;

export type ReadonlyRejectsMissing = Reject<Fits<readonly [Promise<string>], Argument<"readonly">>>;

export type ReadonlyRejectsExtra = Reject<
  Fits<readonly [Promise<string>, Promise<number>, Promise<number>], Argument<"readonly">>
>;

export type OptionalAcceptsOmitted = Assert<Fits<[Promise<string>], Argument<"optional">>>;

export type OptionalAcceptsPresent = Assert<
  Fits<[Promise<string>, Promise<number>], Argument<"optional">>
>;

export type OptionalRejectsWrongOptional = Reject<
  Fits<[Promise<string>, Promise<boolean>], Argument<"optional">>
>;

export type OptionalRejectsExtra = Reject<
  Fits<[Promise<string>, Promise<number>, Promise<number>], Argument<"optional">>
>;

export type VariadicAcceptsEmptyTail = Assert<Fits<[Promise<string>], Argument<"variadic">>>;

export type VariadicAcceptsTail = Assert<
  Fits<[Promise<string>, Promise<number>, Promise<number>], Argument<"variadic">>
>;

export type VariadicRejectsHead = Reject<
  Fits<[Promise<number>, Promise<number>], Argument<"variadic">>
>;

export type VariadicRejectsTail = Reject<
  Fits<[Promise<string>, Promise<boolean>], Argument<"variadic">>
>;

export type ReadonlyVariadicAcceptsTail = Assert<
  Fits<readonly [Promise<string>, Promise<number>], Argument<"readonlyVariadic">>
>;

export type PromiseElementAccepts = Assert<
  Fits<[Promise<string>, Promise<number>], Argument<"promise">>
>;

export type PromiseElementRejects = Reject<
  Fits<[Promise<number>, Promise<number>], Argument<"promise">>
>;
