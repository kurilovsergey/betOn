import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { now, HydratedDocument } from 'mongoose';

export type EvidenceDocument = HydratedDocument<Evidence>;

@Schema()
export class Evidence {
  @Prop({ required: true })
  id_bet: string;

  @Prop({ required: true })
  id_user: string;

  @Prop({ required: true })
  description: string;

  @Prop({ default: now() })
  createdDate: Date;
}

export const EvidenceSchema = SchemaFactory.createForClass(Evidence);
