from pydantic import BaseModel, Field

class NormalizedEvent(BaseModel):
    event_key:str=Field(min_length=1,max_length=255)
    timestamp:str
    event_type:str="unknown"
    username:str|None=None
    source_ip:str|None=None
    host:str|None=None
    outcome:str|None=None
    fields:dict=Field(default_factory=dict)
class ReviewRequest(BaseModel):
    decision:str
    note:str=Field(default="",max_length=4000)
class LookupRequest(BaseModel):
    dataset_id:str=Field(min_length=1,max_length=36)
    kind:str
    value:str=Field(min_length=1,max_length=512)
    authorized:bool=False
