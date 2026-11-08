"use client";

import * as React from "react";

import {
  Loader2Icon,
  PencilIcon,
  PlugZapIcon,
  PlusIcon,
  RefreshCwIcon,
  SaveIcon,
  StarIcon,
  Trash2Icon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";
import type { LLMPoolMember, LLMPoolStatus, LLMProfile, LLMProvider, LLMRetryOverride } from "@/lib/types";
import { cn } from "@/lib/utils";

import { ProfileRetryFields, ZERO_OVERRIDE } from "./retry";

// 思考开关和思考强度各自单独存。空字符串 = 不发送；Select 不接受空 value，用 none 哨兵。
const NONE = "none";
const fromStore = (v?: string) => (v ? v : NONE);
const toStore = (v: string) => (v === NONE ? "" : v);

const FORMATS: { value: LLMProvider["format"]; label: string }[] = [
  { value: "anthropic", label: "Anthropic" },
  { value: "openai", label: "OpenAI (Chat Completions)" },
  { value: "openai-responses", label: "OpenAI (Responses API)" },
];
const THINKING_TYPES = [
  { value: NONE, label: "不发送（默认）" },
  { value: "disabled", label: "关闭" },
  { value: "enabled", label: "开启" },
];
const EFFORT_LEVELS = [
  { value: NONE, label: "不发送（默认）" },
  { value: "low", label: "low" },
  { value: "medium", label: "medium" },
  { value: "high", label: "high" },
  { value: "xhigh", label: "xhigh" },
  { value: "max", label: "max" },
];
const MAX_TOKENS_FIELDS = [
  { value: NONE, label: "max_tokens（默认）" },
  { value: "max_completion_tokens", label: "max_completion_tokens" },
];
const MAX_TOKENS_FIELD_HINTS: Record<string, string> = {
  openai:
    "上限发哪个键。max_tokens 是默认；OpenAI 官方推理模型（o 系列 / GPT-5）只认 max_completion_tokens，收到 max_tokens 会直接报 unsupported_parameter。",
  anthropic: "仅 OpenAI Chat Completions 可选。Anthropic 的字段名固定为 max_tokens。",
  "openai-responses": "仅 OpenAI Chat Completions 可选。Responses API 的字段名固定为 max_output_tokens。",
};

function cooldownText(secs: number) {
  if (secs <= 0) return "";
  if (secs < 60) return `${secs}s`;
  return `${Math.ceil(secs / 60)}min`;
}

type Health = { label: string; cls: string; hint?: string; rank: number };

function healthOf(p: { api_key_hint?: string }, m?: LLMPoolMember): Health {
  if (!p.api_key_hint) {
    return {
      label: "未配置 Key",
      cls: "border-muted-foreground/40 text-muted-foreground",
      hint: "未填 API Key，无法调用",
      rank: 3,
    };
  }
  if (m?.state === "tripped") {
    return {
      label: m.cooldown_secs > 0 ? `已熔断 · ${cooldownText(m.cooldown_secs)}` : "已熔断",
      cls: "border-destructive/50 text-destructive",
      hint: m.last_error,
      rank: 2,
    };
  }
  if (m?.state === "degraded") {
    return {
      label: `异常 · 失败 ${m.fails} 次`,
      cls: "border-amber-500/50 text-amber-600 dark:text-amber-400",
      hint: m.last_error,
      rank: 1,
    };
  }
  return { label: "正常", cls: "border-emerald-500/50 text-emerald-600 dark:text-emerald-400", rank: 0 };
}

// 从接口拉模型列表，勾选后一次性挂到当前提供商。已有的模型勾不上，避免重复建。
function ModelPicker({
  format,
  baseUrl,
  proxy,
  apiKey,
  providerId,
  existing,
  picked,
  onChange,
}: {
  format: string;
  baseUrl: string;
  proxy: string;
  apiKey: string;
  providerId?: number;
  existing: string[];
  picked: string[];
  onChange: (models: string[]) => void;
}) {
  const [loaded, setLoaded] = React.useState<string[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [manual, setManual] = React.useState("");
  const [filter, setFilter] = React.useState("");
  // 地址或密钥一变，上次拉到的列表就对不上了。在渲染里对齐，避免多一次 effect。
  const endpoint = `${format}\0${baseUrl}\0${apiKey}\0${providerId ?? ""}`;
  const [loadedEndpoint, setLoadedEndpoint] = React.useState(endpoint);
  const loadGen = React.useRef(0);
  if (endpoint !== loadedEndpoint) {
    loadGen.current += 1;
    setLoadedEndpoint(endpoint);
    setLoaded([]);
    setLoading(false);
  }

  const existingSet = React.useMemo(() => new Set(existing), [existing]);
  const visible = loaded.filter((m) => !filter.trim() || m.toLowerCase().includes(filter.trim().toLowerCase()));
  const available = loaded.filter((m) => !existingSet.has(m));
  const allOn = available.length > 0 && available.every((m) => picked.includes(m));

  async function load() {
    if (loading) return;
    if (!apiKey.trim() && !providerId) {
      toast.error("先填写 API Key，才能拉取模型列表");
      return;
    }
    const gen = ++loadGen.current;
    setLoading(true);
    try {
      const r = await api.fetchLLMModels({
        provider: format,
        base_url: baseUrl,
        api_key: apiKey,
        proxy,
        provider_id: providerId,
      });
      if (gen !== loadGen.current) return;
      if (r.ok && r.models && r.models.length > 0) {
        setLoaded(r.models);
        toast.success(`拉到 ${r.models.length} 个模型`);
      } else {
        toast.error(`拉取失败：${r.error ?? "接口没有返回模型"}`);
      }
    } catch (e) {
      if (gen !== loadGen.current) return;
      toast.error(`拉取失败：${(e as Error).message}`);
    } finally {
      if (gen === loadGen.current) setLoading(false);
    }
  }

  function toggle(model: string, on: boolean) {
    if (existingSet.has(model)) return;
    if (on) onChange(picked.includes(model) ? picked : [...picked, model]);
    else onChange(picked.filter((m) => m !== model));
  }

  function addManual() {
    const model = manual.trim();
    if (!model) return;
    if (existingSet.has(model)) {
      toast.error("这个模型已经在该提供商下");
      return;
    }
    if (!picked.includes(model)) onChange([...picked, model]);
    setManual("");
  }

  const manualOnly = picked.filter((m) => !loaded.includes(m));

  return (
    <div className="grid gap-3 rounded-lg border p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="grid gap-0.5">
          <Label className="text-sm">要添加的模型</Label>
          <p className="text-muted-foreground text-xs">从接口勾选，或直接填写模型 ID。添加后再单独改上下文和思考。</p>
        </div>
        <Button type="button" size="sm" variant="outline" onClick={() => void load()} disabled={loading}>
          {loading ? <Loader2Icon className="animate-spin" /> : <RefreshCwIcon />}
          拉取列表
        </Button>
      </div>

      {loaded.length > 0 && (
        <div className="grid gap-2">
          <div className="flex items-center gap-2">
            <Input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="筛选模型" className="h-8" />
            <Button
              type="button"
              size="sm"
              variant="ghost"
              disabled={available.length === 0}
              onClick={() => {
                if (allOn) onChange(picked.filter((m) => !available.includes(m)));
                else onChange([...new Set([...picked, ...available])]);
              }}
            >
              {allOn ? "取消全选" : "全选未添加"}
            </Button>
          </div>
          <div className="max-h-56 overflow-y-auto rounded-md border">
            {visible.map((m) => {
              const have = existingSet.has(m);
              const inputId = `pick-${m.replace(/[^a-zA-Z0-9_-]/g, "_")}`;
              return (
                <div key={m} className={cn("flex items-center gap-2 px-2 py-1.5 text-sm", have && "opacity-50")}>
                  <Checkbox
                    id={inputId}
                    checked={have || picked.includes(m)}
                    disabled={have}
                    onCheckedChange={(v) => toggle(m, v === true)}
                  />
                  <label htmlFor={inputId} className="min-w-0 flex-1 truncate font-mono text-xs">
                    {m}
                  </label>
                  {have && <span className="text-muted-foreground text-xs">已添加</span>}
                </div>
              );
            })}
            {visible.length === 0 && <p className="px-2 py-3 text-muted-foreground text-xs">没有匹配的模型</p>}
          </div>
        </div>
      )}

      <div className="flex gap-2">
        <Input
          value={manual}
          onChange={(e) => setManual(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              addManual();
            }
          }}
          placeholder="或输入模型 ID，如 gpt-4o"
          className="font-mono"
        />
        <Button type="button" variant="outline" onClick={addManual}>
          加入
        </Button>
      </div>
      {manualOnly.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {manualOnly.map((m) => (
            <Badge key={m} variant="secondary" className="gap-1 font-mono">
              {m}
              <button
                type="button"
                className="text-muted-foreground"
                onClick={() => toggle(m, false)}
                aria-label={`移除 ${m}`}
              >
                ×
              </button>
            </Badge>
          ))}
        </div>
      )}
      <p className="text-muted-foreground text-xs">已选 {picked.length} 个</p>
    </div>
  );
}

function ProviderSheet({
  provider,
  open,
  onOpenChange,
  onSaved,
}: {
  provider: LLMProvider | null;
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onSaved: () => void;
}) {
  const isNew = !provider;
  const [name, setName] = React.useState("");
  const [format, setFormat] = React.useState<LLMProvider["format"]>("anthropic");
  const [baseUrl, setBaseUrl] = React.useState("");
  const [proxy, setProxy] = React.useState("");
  const [apiKey, setApiKey] = React.useState("");
  const [keyHint, setKeyHint] = React.useState("");
  const [rps, setRps] = React.useState("0");
  const [rpm, setRpm] = React.useState("0");
  const [sessionHeaderKey, setSessionHeaderKey] = React.useState("");
  const [retry, setRetry] = React.useState<LLMRetryOverride>(ZERO_OVERRIDE);
  const [picked, setPicked] = React.useState<string[]>([]);
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    if (!open) return;
    setName(provider?.name ?? "");
    setFormat(provider?.format === "openai" || provider?.format === "openai-responses" ? provider.format : "anthropic");
    setBaseUrl(provider?.base_url ?? "");
    setProxy(provider?.proxy ?? "");
    setRps(String(provider?.rate_per_second ?? 0));
    setRpm(String(provider?.rate_per_minute ?? 0));
    setSessionHeaderKey(provider?.session_header_key ?? "");
    setRetry(provider?.retry ?? ZERO_OVERRIDE);
    setApiKey("");
    setKeyHint(provider?.api_key_hint ?? "");
    setPicked([]);
  }, [open, provider]);

  async function save() {
    if (!name.trim()) {
      toast.error("请填写提供商名称");
      return;
    }
    if (isNew && picked.length === 0) {
      toast.error("请至少添加一个模型");
      return;
    }
    if (saving) return;
    setSaving(true);
    try {
      await api.saveLLMProvider({
        ...(provider ? { id: Number(provider.id) } : {}),
        name: name.trim(),
        format,
        base_url: baseUrl.trim(),
        proxy: proxy.trim(),
        api_key: apiKey,
        rate_per_second: Number(rps) || 0,
        rate_per_minute: Number(rpm) || 0,
        session_header_key: sessionHeaderKey.trim(),
        retry,
        ...(isNew ? { models: picked.map((model) => ({ model, streaming: true })) } : {}),
      });
      toast.success(isNew ? `已创建 ${name.trim()}` : "连接已保存，该提供商下的模型都会用这份连接");
      onSaved();
      onOpenChange(false);
    } catch (e) {
      toast.error(`保存失败：${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="flex flex-col gap-0 p-0 data-[side=right]:sm:max-w-xl">
        <SheetHeader className="px-4">
          <SheetTitle>{isNew ? "新建提供商" : `编辑连接：${provider?.name}`}</SheetTitle>
          <SheetDescription>
            {isNew
              ? "地址、密钥和重试只填这一次。下面勾选的每个模型都会共用它们。"
              : "改动会作用到这个提供商下的全部模型，不用逐个再改。"}
          </SheetDescription>
        </SheetHeader>
        <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto px-4 pb-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="grid gap-2">
              <Label htmlFor="pv-name">名称</Label>
              <Input
                id="pv-name"
                placeholder="例如 OpenRouter"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
            <div className="grid gap-2">
              <Label>格式</Label>
              <Select value={format} onValueChange={(v) => setFormat(v as LLMProvider["format"])}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {FORMATS.map((f) => (
                    <SelectItem key={f.value} value={f.value}>
                      {f.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="pv-base">Base URL（可选）</Label>
            <Input
              id="pv-base"
              className="font-mono"
              placeholder="https://api.openai.com/v1"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="pv-proxy">代理（可选）</Label>
            <Input
              id="pv-proxy"
              className="font-mono"
              placeholder="socks5://user:pass@127.0.0.1:1080"
              value={proxy}
              onChange={(e) => setProxy(e.target.value)}
            />
            <p className="text-muted-foreground text-xs">只作用于这个提供商的出站请求。留空则直连。</p>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="pv-key">API Key</Label>
            <Input
              id="pv-key"
              type="password"
              placeholder={keyHint ? `已设置（${keyHint}），留空保持不变` : "sk-…"}
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
            />
          </div>
          <div className="grid gap-2">
            <Label htmlFor="pv-session">自定义会话头（可选）</Label>
            <Input
              id="pv-session"
              className="font-mono"
              placeholder="如 x-session-id（留空=不发送）"
              value={sessionHeaderKey}
              onChange={(e) => setSessionHeaderKey(e.target.value)}
            />
            <p className="text-muted-foreground text-xs">
              填写头名后，每次请求都带这个 HTTP 头，头值是当前会话的 session id。留空则不发送。
            </p>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="grid gap-2">
              <Label htmlFor="pv-rps">每秒限速</Label>
              <Input id="pv-rps" type="number" min={0} value={rps} onChange={(e) => setRps(e.target.value)} />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="pv-rpm">每分钟限速</Label>
              <Input id="pv-rpm" type="number" min={0} value={rpm} onChange={(e) => setRpm(e.target.value)} />
            </div>
          </div>
          <p className="-mt-2 text-muted-foreground text-xs">限速 0 = 不限，这个提供商下的模型一起算。</p>
          <ProfileRetryFields value={retry} onChange={setRetry} />
          {isNew && (
            <ModelPicker
              format={format}
              baseUrl={baseUrl.trim()}
              proxy={proxy.trim()}
              apiKey={apiKey}
              existing={[]}
              picked={picked}
              onChange={setPicked}
            />
          )}
        </div>
        <div className="flex gap-2 border-t px-4 py-3">
          <Button onClick={() => void save()} disabled={saving} className="flex-1">
            {saving && <Loader2Icon className="animate-spin" />}
            {!saving && isNew && <PlusIcon />}
            {!saving && !isNew && <SaveIcon />}
            {isNew ? "创建" : "保存连接"}
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  );
}

function AddModelsSheet({
  provider,
  open,
  onOpenChange,
  onSaved,
}: {
  provider: LLMProvider | null;
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onSaved: () => void;
}) {
  const [picked, setPicked] = React.useState<string[]>([]);
  const [saving, setSaving] = React.useState(false);

  React.useEffect(() => {
    if (open) setPicked([]);
  }, [open]);

  async function save() {
    if (!provider) return;
    if (picked.length === 0) {
      toast.error("请至少选择一个模型");
      return;
    }
    if (saving) return;
    setSaving(true);
    try {
      const r = await api.addLLMModels(
        provider.id,
        picked.map((model) => ({ model, streaming: true })),
      );
      const added = r.ids?.length ?? 0;
      toast.success(r.skipped ? `已添加 ${added} 个，跳过 ${r.skipped} 个已存在的` : `已添加 ${added} 个模型`);
      onSaved();
      onOpenChange(false);
    } catch (e) {
      toast.error(`添加失败：${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="flex flex-col gap-0 p-0 data-[side=right]:sm:max-w-xl">
        <SheetHeader className="px-4">
          <SheetTitle>添加模型{provider ? ` · ${provider.name}` : ""}</SheetTitle>
          <SheetDescription>新模型直接用这个提供商的地址和密钥，不用再填一遍。</SheetDescription>
        </SheetHeader>
        <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto px-4 pb-4">
          {provider && (
            <ModelPicker
              format={provider.format}
              baseUrl={provider.base_url ?? ""}
              proxy={provider.proxy ?? ""}
              apiKey=""
              providerId={Number(provider.id)}
              existing={provider.models.map((m) => m.model)}
              picked={picked}
              onChange={setPicked}
            />
          )}
        </div>
        <div className="border-t px-4 py-3">
          <Button onClick={() => void save()} disabled={saving || picked.length === 0} className="w-full">
            {saving && <Loader2Icon className="animate-spin" />}
            添加{picked.length > 0 ? ` ${picked.length} 个` : ""}
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  );
}

function ModelSheet({
  provider,
  model,
  open,
  onOpenChange,
  onSaved,
}: {
  provider: LLMProvider | null;
  model: LLMProfile | null;
  open: boolean;
  onOpenChange: (o: boolean) => void;
  onSaved: () => void;
}) {
  const [name, setName] = React.useState("");
  const [modelID, setModelID] = React.useState("");
  const [cw, setCw] = React.useState("0");
  const [thinkingType, setThinkingType] = React.useState(NONE);
  const [effort, setEffort] = React.useState(NONE);
  const [priority, setPriority] = React.useState("0");
  const [poolExclude, setPoolExclude] = React.useState(false);
  const [streaming, setStreaming] = React.useState(true);
  const [maxTokens, setMaxTokens] = React.useState("0");
  const [maxTokensField, setMaxTokensField] = React.useState(NONE);
  const [saving, setSaving] = React.useState(false);
  const [testing, setTesting] = React.useState(false);

  React.useEffect(() => {
    if (!open) return;
    setName(model?.name ?? "");
    setModelID(model?.model ?? "");
    setCw(String(model?.context_window_k ?? 0));
    setThinkingType(fromStore(model?.thinking_type));
    setEffort(fromStore(model?.reasoning_effort));
    setPriority(String(model?.priority ?? 0));
    setPoolExclude(model?.pool_exclude ?? false);
    setStreaming(model?.streaming !== false);
    setMaxTokens(String(model?.max_tokens ?? 0));
    setMaxTokensField(fromStore(model?.max_tokens_field));
  }, [open, model]);

  const format = provider?.format ?? "openai";

  async function testConnection() {
    if (!provider || testing) return;
    if (!modelID.trim()) {
      toast.error("请填写模型 ID");
      return;
    }
    setTesting(true);
    try {
      const r = await api.testLLM({
        provider: format,
        model: modelID.trim(),
        base_url: provider.base_url ?? "",
        proxy: provider.proxy ?? "",
        thinking_type: toStore(thinkingType),
        reasoning_effort: toStore(effort),
        profile_id: model ? Number(model.id) : undefined,
        provider_id: Number(provider.id),
        streaming,
        session_header_key: provider.session_header_key ?? "",
      });
      if (r.ok) {
        toast.success(`连接成功 · ${r.latency_ms ?? "?"}ms · ${r.model ?? modelID}`, {
          description: r.reply ? `回复：${r.reply}` : undefined,
        });
      } else toast.error(`连接失败：${r.error ?? "未知"}`);
    } catch (e) {
      toast.error(`测试出错：${(e as Error).message}`);
    } finally {
      setTesting(false);
    }
  }

  async function save() {
    if (!model) return;
    if (!name.trim() || !modelID.trim()) {
      toast.error("请填写名称和模型 ID");
      return;
    }
    if (saving) return;
    setSaving(true);
    try {
      await api.updateLLMModel(model.id, {
        name: name.trim(),
        model: modelID.trim(),
        context_window_k: Number(cw) || 0,
        thinking_type: toStore(thinkingType),
        reasoning_effort: toStore(effort),
        priority: Number(priority) || 0,
        pool_exclude: poolExclude,
        streaming,
        max_tokens: Math.max(0, Number(maxTokens) || 0),
        max_tokens_field: format === "openai" ? toStore(maxTokensField) : "",
      });
      toast.success("已保存");
      onSaved();
      onOpenChange(false);
    } catch (e) {
      toast.error(`保存失败：${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="flex flex-col gap-0 p-0 data-[side=right]:sm:max-w-xl">
        <SheetHeader className="px-4">
          <SheetTitle className="flex items-center gap-2">
            {model ? `编辑模型：${model.name}` : "编辑模型"}
            {model?.is_default && (
              <Badge variant="outline" className="border-amber-400/50 text-amber-500">
                激活中
              </Badge>
            )}
          </SheetTitle>
          <SheetDescription>只改这个模型。地址和密钥在提供商「{provider?.name ?? ""}」上，这里不动。</SheetDescription>
        </SheetHeader>
        <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto px-4 pb-4">
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="grid gap-2">
              <Label htmlFor="md-name">显示名称</Label>
              <Input id="md-name" value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="md-model">模型 ID</Label>
              <Input id="md-model" className="font-mono" value={modelID} onChange={(e) => setModelID(e.target.value)} />
            </div>
          </div>
          <div className="grid gap-2">
            <Label htmlFor="md-cw">上下文窗口 (K)</Label>
            <Input id="md-cw" type="number" min={0} max={1000} value={cw} onChange={(e) => setCw(e.target.value)} />
            <p className="text-muted-foreground text-xs">
              单位是 K。0 = 默认 200K，上限 1000。只影响这个模型的压缩阈值。
            </p>
          </div>
          <div className="grid gap-3 rounded-lg border p-3">
            <div className="flex items-center justify-between gap-4">
              <div className="grid gap-0.5">
                <Label className="text-sm">思考开关</Label>
                <p className="text-muted-foreground text-xs">不发送 = 不带 thinking 字段。和下面的强度互不影响。</p>
              </div>
              <Select value={thinkingType} onValueChange={setThinkingType}>
                <SelectTrigger className="w-36 shrink-0">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {THINKING_TYPES.map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center justify-between gap-4 border-t pt-3">
              <div className="grid gap-0.5">
                <Label className="text-sm">思考强度</Label>
                <p className="text-muted-foreground text-xs">reasoning_effort。有的接口只靠强度就能开思考。</p>
              </div>
              <Select value={effort} onValueChange={setEffort}>
                <SelectTrigger className="w-36 shrink-0">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {EFFORT_LEVELS.map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="grid gap-3 rounded-lg border p-3">
            <div className="flex items-center justify-between gap-4">
              <div className="grid gap-0.5">
                <Label htmlFor="md-pri" className="text-sm">
                  轮询优先级
                </Label>
                <p className="text-muted-foreground text-xs">数字越大越先被选中。激活模型恒为第 1 顺位。</p>
              </div>
              <Input
                id="md-pri"
                type="number"
                className="w-24"
                value={priority}
                onChange={(e) => setPriority(e.target.value)}
              />
            </div>
            <div className="flex items-center justify-between gap-4 border-t pt-3">
              <div className="grid gap-0.5">
                <Label className="text-sm">不参与轮询</Label>
                <p className="text-muted-foreground text-xs">开启后不会被当作故障转移目标，仍可被任务或 Agent 指定。</p>
              </div>
              <Switch checked={poolExclude} onCheckedChange={setPoolExclude} aria-label="不参与轮询" />
            </div>
            <div className="flex items-center justify-between gap-4 border-t pt-3">
              <div className="grid gap-0.5">
                <Label className="text-sm">流式输出</Label>
                <p className="text-muted-foreground text-xs">关闭则走非流式，适合 SSE 不稳定的网关。只影响这个模型。</p>
              </div>
              <Switch checked={streaming} onCheckedChange={setStreaming} aria-label="流式输出" />
            </div>
          </div>
          <div className="grid gap-3 rounded-lg border p-3">
            <div className="flex items-center justify-between gap-4">
              <div className="grid gap-0.5">
                <Label htmlFor="md-max" className="text-sm">
                  输出上限
                </Label>
                <p className="text-muted-foreground text-xs">
                  单次回复的 token 上限，会随请求发出。0 = 不发送，由服务端默认。
                </p>
              </div>
              <Input
                id="md-max"
                type="number"
                min={0}
                className="w-28"
                value={maxTokens}
                onChange={(e) => setMaxTokens(e.target.value)}
              />
            </div>
            <div className="flex items-center justify-between gap-4 border-t pt-3">
              <div className="grid gap-0.5">
                <Label className="text-sm">上限字段名</Label>
                <p className="text-muted-foreground text-xs">{MAX_TOKENS_FIELD_HINTS[format]}</p>
              </div>
              <Select
                value={format === "openai" ? maxTokensField : NONE}
                onValueChange={setMaxTokensField}
                disabled={format !== "openai"}
              >
                <SelectTrigger className="w-56 shrink-0">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {MAX_TOKENS_FIELDS.map((o) => (
                    <SelectItem key={o.value} value={o.value}>
                      {o.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
        </div>
        <div className="flex gap-2 border-t px-4 py-3">
          <Button variant="outline" onClick={() => void testConnection()} disabled={testing}>
            {testing ? <Loader2Icon className="animate-spin" /> : <PlugZapIcon />}
            {testing ? "测试中…" : "测试"}
          </Button>
          <Button onClick={() => void save()} disabled={saving} className="flex-1">
            {saving ? <Loader2Icon className="animate-spin" /> : <SaveIcon />}
            保存
          </Button>
        </div>
      </SheetContent>
    </Sheet>
  );
}

export function ProviderBoard({
  providers,
  pool,
  onReload,
}: {
  providers: LLMProvider[];
  pool: LLMPoolStatus | null;
  onReload: () => Promise<void>;
}) {
  const [query, setQuery] = React.useState("");
  const [providerOpen, setProviderOpen] = React.useState(false);
  const [editing, setEditing] = React.useState<LLMProvider | null>(null);
  const [addOpen, setAddOpen] = React.useState(false);
  const [addFor, setAddFor] = React.useState<LLMProvider | null>(null);
  const [modelOpen, setModelOpen] = React.useState(false);
  const [modelProvider, setModelProvider] = React.useState<LLMProvider | null>(null);
  const [modelEditing, setModelEditing] = React.useState<LLMProfile | null>(null);
  const [confirmDelete, setConfirmDelete] = React.useState<string | null>(null);
  const [testingID, setTestingID] = React.useState<string | null>(null);

  const health = React.useMemo(() => {
    const m = new Map<string, LLMPoolMember>();
    for (const c of pool?.chain ?? []) m.set(c.profile_id, c);
    return m;
  }, [pool]);

  const poolOn = pool?.enabled ?? false;
  const q = query.trim().toLowerCase();
  const shown = providers.filter((p) => {
    if (!q) return true;
    if (p.name.toLowerCase().includes(q)) return true;
    if ((p.base_url ?? "").toLowerCase().includes(q)) return true;
    return p.models.some((m) => m.name.toLowerCase().includes(q) || m.model.toLowerCase().includes(q));
  });

  function openCreate() {
    setEditing(null);
    setProviderOpen(true);
  }
  function openEdit(p: LLMProvider) {
    setEditing(p);
    setProviderOpen(true);
  }
  function openAdd(p: LLMProvider) {
    setAddFor(p);
    setAddOpen(true);
  }
  function openModel(p: LLMProvider, m: LLMProfile) {
    setModelProvider(p);
    setModelEditing(m);
    setModelOpen(true);
  }

  async function activate(m: LLMProfile) {
    try {
      await api.activateLLMProfile(m.id);
      toast.success(`已激活：${m.name}`);
      await onReload();
    } catch (e) {
      toast.error(`激活失败：${(e as Error).message}`);
    }
  }

  async function removeModel(p: LLMProvider, m: LLMProfile) {
    if (m.is_default) {
      toast.error("无法删除当前激活的模型，请先激活其他模型");
      return;
    }
    try {
      await api.deleteLLMProfile(m.id);
      toast.success(p.models.length === 1 ? `已删除 ${m.name}，提供商已一并移除` : `已删除 ${m.name}`);
      await onReload();
    } catch (e) {
      toast.error(`删除失败：${(e as Error).message}`);
    }
  }

  async function removeProvider(p: LLMProvider) {
    if (p.models.some((m) => m.is_default)) {
      toast.error("该提供商下有当前激活的模型，请先激活其他模型");
      setConfirmDelete(null);
      return;
    }
    try {
      await api.deleteLLMProvider(p.id);
      toast.success(`已删除提供商 ${p.name}`);
      setConfirmDelete(null);
      await onReload();
    } catch (e) {
      toast.error(`删除失败：${(e as Error).message}`);
    }
  }

  async function testModel(p: LLMProvider, m: LLMProfile) {
    if (testingID) return;
    setTestingID(m.id);
    try {
      const r = await api.testLLM({
        provider: p.format,
        model: m.model,
        base_url: p.base_url ?? "",
        proxy: p.proxy ?? "",
        thinking_type: m.thinking_type ?? "",
        reasoning_effort: m.reasoning_effort ?? "",
        profile_id: Number(m.id),
        streaming: m.streaming !== false,
        session_header_key: p.session_header_key ?? "",
      });
      if (r.ok) {
        toast.success(`${m.name} 连接成功 · ${r.latency_ms ?? "?"}ms`, {
          description: r.reply ? `回复：${r.reply}` : undefined,
        });
      } else toast.error(`${m.name} 连接失败：${r.error ?? "未知"}`);
    } catch (e) {
      toast.error(`测试出错：${(e as Error).message}`);
    } finally {
      setTestingID(null);
    }
  }

  return (
    <div className="grid gap-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <Input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="搜索提供商或模型"
          className="h-8 max-w-xs"
        />
        <Button size="sm" onClick={openCreate}>
          <PlusIcon /> 新建提供商
        </Button>
      </div>

      {shown.map((p) => {
        const worst = p.models.reduce<Health | null>(
          (acc, m) => {
            const h = healthOf(p, health.get(m.id));
            if (!acc || h.rank > acc.rank) return h;
            return acc;
          },
          p.models.length === 0 ? healthOf(p) : null,
        );
        const headerHealth = worst ?? healthOf(p);
        const models = [...p.models].sort(
          (a, b) => Number(b.is_default) - Number(a.is_default) || a.name.localeCompare(b.name, "zh"),
        );
        const hasActive = p.models.some((m) => m.is_default);
        return (
          <section key={p.id} className={cn("rounded-xl border bg-card", hasActive && "border-amber-400/50")}>
            <div className="flex flex-wrap items-start justify-between gap-3 border-b px-4 py-3">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <h2 className="font-medium">{p.name}</h2>
                  <Badge variant="outline">{FORMATS.find((f) => f.value === p.format)?.label ?? p.format}</Badge>
                  <Badge variant="outline" className={headerHealth.cls} title={headerHealth.hint}>
                    {headerHealth.label}
                  </Badge>
                </div>
                <p className="mt-1 truncate font-mono text-muted-foreground text-xs">{p.base_url || "官方默认地址"}</p>
                <p className="mt-1 flex flex-wrap gap-x-3 text-muted-foreground text-xs">
                  <span>{p.models.length} 个模型</span>
                  {p.api_key_hint && <span>{p.api_key_hint}</span>}
                  {(p.rate_per_second > 0 || p.rate_per_minute > 0) && (
                    <span>
                      {p.rate_per_second}/s · {p.rate_per_minute}/min
                    </span>
                  )}
                  {p.proxy && <span className="truncate">代理 {p.proxy}</span>}
                  {p.session_header_key && <span>会话头 {p.session_header_key}</span>}
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <Button size="sm" variant="outline" onClick={() => openEdit(p)}>
                  <PencilIcon /> 编辑连接
                </Button>
                {confirmDelete === p.id ? (
                  <>
                    <Button size="sm" variant="destructive" onClick={() => void removeProvider(p)}>
                      确认删除
                    </Button>
                    <Button size="sm" variant="ghost" onClick={() => setConfirmDelete(null)}>
                      取消
                    </Button>
                  </>
                ) : (
                  <Button size="sm" variant="ghost" onClick={() => setConfirmDelete(p.id)}>
                    <Trash2Icon className="text-destructive" /> 删除
                  </Button>
                )}
              </div>
            </div>

            <div className="grid gap-2 p-3">
              {models.map((m) => {
                const h = healthOf(p, health.get(m.id));
                return (
                  <div
                    key={m.id}
                    className={cn(
                      "grid gap-2 rounded-lg border px-3 py-2.5 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center",
                      m.is_default && "border-amber-400/40 bg-amber-400/5",
                    )}
                  >
                    <div className="min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <StarIcon
                          className={cn(
                            "size-3.5 shrink-0",
                            m.is_default ? "fill-amber-400 text-amber-400" : "text-muted-foreground",
                          )}
                        />
                        <span className="font-medium text-sm">{m.name}</span>
                        <code className="truncate font-mono text-muted-foreground text-xs">{m.model}</code>
                        {m.is_default && (
                          <Badge variant="outline" className="border-amber-400/50 text-amber-500">
                            激活
                          </Badge>
                        )}
                        <Badge variant="outline" className={cn("ml-auto sm:ml-0", h.cls)} title={h.hint}>
                          {h.label}
                        </Badge>
                      </div>
                      <p className="mt-1 flex flex-wrap gap-x-3 pl-5 text-muted-foreground text-xs">
                        <span>上下文 {m.context_window_k ? `${m.context_window_k}K` : "默认"}</span>
                        {m.thinking_type && <span>思考 {m.thinking_type === "enabled" ? "开" : "关"}</span>}
                        {m.reasoning_effort && <span>强度 {m.reasoning_effort}</span>}
                        {(m.max_tokens ?? 0) > 0 && <span>输出上限 {m.max_tokens}</span>}
                        {m.streaming === false && <span>非流式</span>}
                        {poolOn &&
                          !m.is_default &&
                          (m.pool_exclude ? <span>不参与轮询</span> : <span>优先级 {m.priority ?? 0}</span>)}
                      </p>
                    </div>
                    <div className="flex flex-wrap gap-1.5 sm:justify-end">
                      <Button size="sm" variant="outline" disabled={m.is_default} onClick={() => void activate(m)}>
                        {m.is_default ? "已激活" : "设为激活"}
                      </Button>
                      <Button
                        size="sm"
                        variant="ghost"
                        disabled={testingID === m.id}
                        onClick={() => void testModel(p, m)}
                      >
                        {testingID === m.id ? <Loader2Icon className="animate-spin" /> : <PlugZapIcon />}
                        测试
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => openModel(p, m)}>
                        编辑
                      </Button>
                      <Button
                        size="icon"
                        variant="ghost"
                        aria-label={`删除 ${m.name}`}
                        onClick={() => void removeModel(p, m)}
                      >
                        <Trash2Icon className="text-destructive" />
                      </Button>
                    </div>
                  </div>
                );
              })}
              {models.length === 0 && (
                <p className="px-1 py-2 text-muted-foreground text-sm">这个提供商下还没有模型。</p>
              )}
              <div>
                <Button size="sm" variant="outline" onClick={() => openAdd(p)}>
                  <PlusIcon /> 添加模型
                </Button>
              </div>
            </div>
          </section>
        );
      })}

      {providers.length === 0 && (
        <div className="rounded-lg border border-dashed p-10 text-center text-muted-foreground text-sm">
          还没有提供商。新建一个，把要用的模型一次加上。
        </div>
      )}
      {providers.length > 0 && shown.length === 0 && (
        <div className="rounded-lg border border-dashed p-6 text-center text-muted-foreground text-sm">
          没有匹配的提供商或模型
        </div>
      )}

      <ProviderSheet
        provider={editing}
        open={providerOpen}
        onOpenChange={setProviderOpen}
        onSaved={() => void onReload()}
      />
      <AddModelsSheet
        key={addFor?.id ?? "add"}
        provider={addFor}
        open={addOpen}
        onOpenChange={setAddOpen}
        onSaved={() => void onReload()}
      />
      <ModelSheet
        provider={modelProvider}
        model={modelEditing}
        open={modelOpen}
        onOpenChange={setModelOpen}
        onSaved={() => void onReload()}
      />
    </div>
  );
}
