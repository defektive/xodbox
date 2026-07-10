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
