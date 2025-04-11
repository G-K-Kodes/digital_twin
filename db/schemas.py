from sqlalchemy import Column, Integer, Float, String
from .connection import Base

class Netflow(Base):
    __tablename__ = "netflows"

    id = Column(Integer, primary_key=True, index=True)
    flow_id = Column(String)
    flow_duration = Column(Integer)
    total_fwd_packet = Column(Integer)
    total_bwd_packets = Column(Integer)
    fwd_packet_length_mean = Column(Float)
    fwd_packet_length_std = Column(Float)
    bwd_packet_length_mean = Column(Float)
    bwd_packet_length_std = Column(Float)
    flow_bytes_per_s = Column(Float)
    flow_packets_per_s = Column(Float)
    flow_iat_mean = Column(Float)
    flow_iat_std = Column(Float)
    fwd_iat_mean = Column(Float)
    fwd_iat_std = Column(Float)
    bwd_iat_total = Column(Float)
    bwd_iat_mean = Column(Float)
    bwd_iat_std = Column(Float)
    fwd_packets_per_s = Column(Float)
    bwd_packets_per_s = Column(Float)
    packet_length_mean = Column(Float)
    packet_length_std = Column(Float)
    fin_flag_count = Column(Integer)
    syn_flag_count = Column(Integer)
    rst_flag_count = Column(Integer)
    psh_flag_count = Column(Integer)
    ack_flag_count = Column(Integer)
    urg_flag_count = Column(Integer)
    cwr_flag_count = Column(Integer)
    ece_flag_count = Column(Integer)
    down_up_ratio = Column(Float)
    subflow_fwd_packets = Column(Integer)
    subflow_fwd_bytes = Column(Integer)
    subflow_bwd_packets = Column(Integer)
    subflow_bwd_bytes = Column(Integer)
    active_mean = Column(Float)
    active_std = Column(Float)
    idle_mean = Column(Float)
    idle_std = Column(Float)
    prediction = Column(String)

    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}

class Payload(Base):
    __tablename__ = "payloads"

    id = Column(Integer, primary_key=True, index=True)
    flow_id = Column(String)
    stime = Column(Integer)
    timestamp = Column(String)
    prediction = Column(String)

    def to_dict(self):
        return {column.name: getattr(self, column.name) for column in self.__table__.columns}