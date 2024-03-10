import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { now, HydratedDocument } from 'mongoose';

export type CategoryDocument = HydratedDocument<Category>;

@Schema()
export class Category {
  @Prop({ required: true, unique: true })
  name: string;

  @Prop({ required: false, default: null })
  emoji: string | null;

  @Prop({ default: now() })
  createdDate: Date;
}

export const CategorySchema = SchemaFactory.createForClass(Category);
