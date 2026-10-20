export async function api<T>(path:string,init?:RequestInit):Promise<T>{const response=await fetch(`/api/v1${path}`,init);const body=await response.json().catch(()=>({error:'Unexpected API response'}));if(!response.ok)throw new Error(body.error||`Request failed (${response.status})`);return body as T}
export type Dataset={id:string;name:string;data_type:string;event_count:number;status:string;created_at?:string;error?:string};
export type Incident={id:string;dataset_id:string;title:string;severity:string;status:string;first_seen:string;last_seen:string;summary:string;indicators:string[]};
