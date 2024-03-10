import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { now, HydratedDocument } from 'mongoose';

export type BidDocument = HydratedDocument<Bid>;

@Schema()
export class Bid {
  @Prop({ required: true })
  id_bet: string;

  //кто предложил пари
  @Prop({ required: true })
  id_offered_user: string;

  //кто поспорил
  @Prop({ required: true })
  id_argued_user: string;

  @Prop({ required: true })
  sum: number;

  @Prop({ default: null })
  id_winner: string | null;

  @Prop({ default: now() })
  createdDate: Date;
}

export const BidSchema = SchemaFactory.createForClass(Bid);
