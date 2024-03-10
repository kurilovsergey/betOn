import { Module } from '@nestjs/common';
import { EvidencesService } from './evidences.service';
import { EvidencesController } from './evidences.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { Evidence, EvidenceSchema } from './schemas/evidence.schema';
import { BetsModule } from '../bets/bets.module';
import { UsersModule } from '../users/users.module';

@Module({
  controllers: [EvidencesController],
  providers: [EvidencesService],
  imports: [
    MongooseModule.forFeature([
      { name: Evidence.name, schema: EvidenceSchema },
    ]),
    BetsModule,
    UsersModule,
  ],
})
export class EvidencesModule {}
