import { Point, PointHex, StringifiedType, TorusServiceProviderArgs } from "@tkey-mpc/common-types";
import { ServiceProviderBase } from "@tkey-mpc/service-provider-base";
import type { TORUS_SAPPHIRE_NETWORK_TYPE } from "@toruslabs/constants";
import {
  AggregateLoginParams,
  CustomAuth,
  CustomAuthArgs,
  InitParams,
  SubVerifierDetails,
  TorusAggregateLoginResponse,
  TorusLoginResponse,
} from "@toruslabs/customauth";
import { Torus, TorusPublicKey } from "@toruslabs/torus.js";
import BN from "bn.js";

export class TorusServiceProvider extends ServiceProviderBase {
  customAuthInstance: CustomAuth;

  singleLoginKey: BN;

  customAuthArgs: CustomAuthArgs & { network: TORUS_SAPPHIRE_NETWORK_TYPE };

  verifierType?: "normal" | "aggregate" | "hybrid";

  constructor({ enableLogging = false, postboxKey, customAuthArgs, useTSS }: TorusServiceProviderArgs) {
    super({ enableLogging, postboxKey, useTSS });
    this.customAuthArgs = customAuthArgs;
    this.customAuthInstance = new CustomAuth(customAuthArgs);
    this.serviceProviderName = "TorusServiceProvider";
  }

  static fromJSON(value: StringifiedType): TorusServiceProvider {
    const { enableLogging, postboxKey, customAuthArgs, serviceProviderName } = value;
    if (serviceProviderName !== "TorusServiceProvider") return undefined;

    return new TorusServiceProvider({
      enableLogging,
      postboxKey,
      customAuthArgs,
    });
  }

  async init(params: InitParams): Promise<void> {
    return this.customAuthInstance.init(params);
  }

  _setTSSPubKey(tssTag: string, tssNonce: number, tssPubKey: Point): void {
    throw new Error(`this method has been overriden and should not be called with ${tssTag}, ${tssNonce}, ${tssPubKey}`);
  }

  retrieveVerifierId(): string {
    if (!this.verifierId) throw new Error("no verifierId, not logged in");
    return this.verifierId;
  }

  _setTSSNodeDetails(serverEndpoints: string[], serverPubKeys: PointHex[], serverThreshold: number): void {
    throw new Error(`this method has been overriden and should not be called with ${serverEndpoints}, ${serverPubKeys}, ${serverThreshold}`);
  }

  async getTSSNodeDetails(): Promise<{ serverEndpoints: string[]; serverPubKeys: PointHex[]; serverThreshold: number }> {
    if (!this.verifierId) throw new Error("no verifierId, not logged in");
    if (!this.verifierName) throw new Error("no verifierName, not logged in");

    const { torusNodeTSSEndpoints: tssNodeEndpoints, torusNodePub: torusPubKeys } = await this.customAuthInstance.nodeDetailManager.getNodeDetails({
      verifier: this.verifierName,
      verifierId: this.verifierId,
    });

    return {
      serverEndpoints: tssNodeEndpoints,
      serverPubKeys: torusPubKeys.map((key) => {
        return {
          x: key.X,
          y: key.Y,
        };
      }),
      serverThreshold: Math.ceil(tssNodeEndpoints.length / 2),
    };
  }

  async getSSSNodeDetails(): Promise<{ serverEndpoints: string[]; serverPubKeys: PointHex[]; serverThreshold: number }> {
    if (!this.verifierId) throw new Error("no verifierId, not logged in");
    if (!this.verifierName) throw new Error("no verifierName, not logged in");

    const { torusNodeSSSEndpoints: tssNodeEndpoints, torusNodePub: torusPubKeys } =
      this.customAuthInstance?.config?.nodeDetails ||
      (await this.customAuthInstance.nodeDetailManager.getNodeDetails({
        verifier: this.verifierName,
        verifierId: this.verifierId,
      }));
    return {
      serverEndpoints: tssNodeEndpoints,
      serverPubKeys: torusPubKeys.map((key) => {
        return {
          x: key.X,
          y: key.Y,
        };
      }),
      serverThreshold: Math.ceil(tssNodeEndpoints.length / 2),
    };
  }

  async getRSSNodeDetails(): Promise<{ serverEndpoints: string[]; serverPubKeys: PointHex[]; serverThreshold: number }> {
    if (!this.verifierId) throw new Error("no verifierId, not logged in");
    if (!this.verifierName) throw new Error("no verifierName, not logged in");

    const { torusNodeRSSEndpoints: tssNodeEndpoints, torusNodePub: torusPubKeys } =
      this.customAuthInstance?.config?.nodeDetails ||
      (await this.customAuthInstance.nodeDetailManager.getNodeDetails({
        verifier: this.verifierName,
        verifierId: this.verifierId,
      }));

    return {
      serverEndpoints: tssNodeEndpoints,
      serverPubKeys: torusPubKeys.map((key) => {
        return {
          x: key.X,
          y: key.Y,
        };
      }),
      serverThreshold: Math.ceil(tssNodeEndpoints.length / 2),
    };
  }

  async getTSSPubKey(
    tssTag: string,
    tssNonce: number
  ): Promise<{
    pubKey: Point;
    nodeIndexes?: number[];
  }> {
    if (!this.verifierName || !this.verifierId) throw new Error("verifier userinfo not found, not logged in yet");
    const { serverEndpoints: sssNodeEndpoints } = await this.getSSSNodeDetails();
    const tssServerPub = (await this.customAuthInstance.torus.getPublicAddress(
      sssNodeEndpoints,
      this.sssNodeDetails.serverPubKeys.map((node) => ({ X: node.x, Y: node.y })),
      {
        verifier: this.verifierName,
        verifierId: this.verifierId,
        extendedVerifierId: `${this.verifierId}\u0015${tssTag || "default"}\u0016${tssNonce || 0}`,
      }
    )) as TorusPublicKey;

    return {
      pubKey: new Point(tssServerPub.finalKeyData.X, tssServerPub.finalKeyData.Y),
      nodeIndexes: tssServerPub.nodesData.nodeIndexes || [],
    };
  }

  async triggerLogin(params: SubVerifierDetails): Promise<TorusLoginResponse> {
    const obj = await this.customAuthInstance.triggerLogin(params);
    // incase of redirectflow which return null
    if (!obj) return;

    const localPrivKey = Torus.getPostboxKey(obj);
    this.postboxKey = new BN(localPrivKey, "hex");
    const { verifier, verifierId } = obj.userInfo;
    this.verifierName = verifier;
    this.verifierId = verifierId;
    this.verifierType = "normal";
    return obj;
  }

  async triggerAggregateLogin(params: AggregateLoginParams): Promise<TorusAggregateLoginResponse> {
    const obj = await this.customAuthInstance.triggerAggregateLogin(params);
    // incase of redirectflow which return null
    if (!obj) return;

    const localPrivKey = Torus.getPostboxKey(obj);
    this.postboxKey = new BN(localPrivKey, "hex");
    const { aggregateVerifier, verifierId } = obj.userInfo[0];
    this.verifierName = aggregateVerifier;
    this.verifierId = verifierId;
    this.verifierType = "aggregate";
    return obj;
  }

  toJSON(): StringifiedType {
    return {
      ...super.toJSON(),
      serviceProviderName: this.serviceProviderName,
      customAuthArgs: this.customAuthArgs,
    };
  }
}
