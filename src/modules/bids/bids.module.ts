import { Module } from '@nestjs/common';
import { BidsService } from './bids.service';
import { BidsController } from './bids.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { Bid, BidSchema } from './schemas/bid.schema';
import { UsersModule } from 'src/modules/users/users.module';
import { BetsModule } from 'src/modules/bets/bets.module';

@Module({
  controllers: [BidsController],
  providers: [BidsService],
  imports: [
    MongooseModule.forFeature([{ name: Bid.name, schema: BidSchema }]),
    UsersModule,
    BetsModule,
  ],
})
export class BidsModule {}
