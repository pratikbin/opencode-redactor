declare const plugin: ((input: any) => Promise<any>) & {
  maskSecrets?: (text: unknown) => {
    masked: string;
    report: { triggered: boolean; countsByLabel: Record<string, number> };
  };
};

export default plugin;
