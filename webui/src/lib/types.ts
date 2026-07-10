export interface InteractionSummary {
  id: number;
  created_at: string;
  remote_addr: string;
  remote_port: string;
  handler: string;
  request_type: string;
  request_target: string;
  protocol: string;
  user_agent: string;
}

export interface InteractionDetail extends InteractionSummary {
  headers: string;
  body: string;
  curl: string;
}

export interface InteractionPage {
  items: InteractionSummary[];
  total: number;
  limit: number;
  offset: number;
}

export interface Bot {
  remote_addr: string;
  total: number;
  minute_group: number;
}

export interface UserRow {
  id: number;
  username: string;
  role: string;
}

export interface ApiKey {
  id: number;
  name: string;
  prefix: string;
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
}

export interface Sink {
  slug: string;
  description: string;
  created_at: string;
  event_count: number;
}

export interface SinkDetail extends Sink {
  events: InteractionDetail[];
  total: number;
  limit: number;
  offset: number;
}

export interface Payload {
  id: number;
  name: string;
  description: string;
  type: string;
  pattern: string;
  is_final: boolean;
  sort_order: number;
  internal_function: string;
  headers: Record<string, string> | null;
  body: string;
  status_code: string;
}
