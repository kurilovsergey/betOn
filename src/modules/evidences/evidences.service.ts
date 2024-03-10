import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Evidence } from './schemas/evidence.schema';
import { Model } from 'mongoose';
import { BetsService } from '../bets/bets.service';
import { UsersService } from '../users/users.service';
import { CreateEvidenceDto } from './dto/create-evidence.dto';

@Injectable()
export class EvidencesService {
  constructor(
    @InjectModel(Evidence.name) private evidencesModel: Model<Evidence>,
    private readonly betsService: BetsService,
    private readonly usersService: UsersService,
  ) {}

  async getEvidencesByIdBet(id_bet: string): Promise<Evidence[]> {
    try {
      await this.betsService.checkBetById(id_bet);
      return await this.evidencesModel.find({ id_bet });
    } catch (e) {
      throw new Error(e);
    }
  }

  async getEvidencesByIdBetAndIdUser(
    id_bet: string,
    id_user: string,
  ): Promise<Evidence[]> {
    try {
      await this.betsService.checkBetById(id_bet);
      await this.usersService.checkUserById(id_user);
      return await this.evidencesModel.find({ id_bet, id_user });
    } catch (e) {
      throw new Error(e);
    }
  }

  async createEvidence(
    createEvidenceDto: CreateEvidenceDto,
  ): Promise<Evidence> {
    try {
      await this.betsService.checkBetById(createEvidenceDto.id_bet);
      await this.usersService.checkUserById(createEvidenceDto.id_user);
      const newEvidence = await new this.evidencesModel(
        createEvidenceDto,
      ).save();
      return newEvidence;
    } catch (e) {
      throw new Error(e);
    }
  }
}
