import { Module } from '@nestjs/common';
import { BetsService } from './bets.service';
import { BetsController } from './bets.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { Bet, BetSchema } from './schemas/bet.schema';
import { UsersModule } from 'src/modules/users/users.module';
import { CategoriesModule } from 'src/modules/categories/categories.module';

@Module({
  controllers: [BetsController],
  providers: [BetsService],
  imports: [
    MongooseModule.forFeature([{ name: Bet.name, schema: BetSchema }]),
    UsersModule,
    CategoriesModule,
  ],
  exports: [BetsService],
})
export class BetsModule {}
