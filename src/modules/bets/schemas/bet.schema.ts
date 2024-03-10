import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { now, HydratedDocument } from 'mongoose';

export type BetDocument = HydratedDocument<Bet>;

@Schema()
export class Bet {
  @Prop({ required: true, default: false })
  status: boolean;

  @Prop({ required: true })
  id_user: string;

  @Prop()
  description: string;

  @Prop({ required: true })
  sum: number;

  @Prop({ default: null })
  categories: string[] | null;

  @Prop({ default: now() })
  createdDate: Date;

  @Prop()
  endDate: Date;
}

export const BetSchema = SchemaFactory.createForClass(Bet);
