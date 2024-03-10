import { BadRequestException, Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Bid } from './schemas/bid.schema';
import { Model } from 'mongoose';
import { UsersService } from 'src/modules/users/users.service';
import { CreateBidDto } from './dto/create-bid.dto';
import { BetsService } from 'src/modules/bets/bets.service';
import { checkIdForMongo } from 'src/tools/functions';
import { CalculateBidDto } from './dto/calculation-bid.dto';

@Injectable()
export class BidsService {
  constructor(
    @InjectModel(Bid.name) private bidsModel: Model<Bid>,
    private readonly usersService: UsersService,
    private readonly betsService: BetsService,
  ) {}

  async getAllBids(): Promise<Bid[]> {
    try {
      return await this.bidsModel.find();
    } catch (e) {
      throw new Error(e);
    }
  }

  async getByIdBid(id: string): Promise<Bid> {
    try {
      checkIdForMongo(id);
      return await this.bidsModel.findById(id);
    } catch (e) {
      throw new Error(e);
    }
  }

  async createBid(createBidDto: CreateBidDto, id_bet: string): Promise<Bid> {
    try {
      await this.betsService.checkBetById(id_bet);
      await this.usersService.checkUserById(createBidDto.id_offered_user);
      await this.usersService.checkUserById(createBidDto.id_argued_user);
      await this.betsService.checkBetAndUserById(
        id_bet,
        createBidDto.id_offered_user,
      );
      const newBid = await new this.bidsModel({
        id_bet: id_bet,
        id_offered_user: createBidDto.id_offered_user,
        id_argued_user: createBidDto.id_argued_user,
        sum: createBidDto.sum,
      }).save();
      return newBid;
    } catch (e) {
      throw new Error(e);
    }
  }

  async calculationBid(calculateBidDto: CalculateBidDto): Promise<boolean> {
    try {
      //получаю информацию по ставке
      const bid = await this.getByIdBid(calculateBidDto.id_bid);

      // победитель тот, кто предложил пари - offeredUserWin
      let idWinner = bid.id_offered_user;
      let idLoser = bid.id_argued_user;
      if (!calculateBidDto.offeredUserWin) {
        idWinner = bid.id_argued_user;
        idLoser = bid.id_offered_user;
      }
      //получение новых балансов победителя и проигравшего
      const newBalanceWin =
        (await this.usersService.getUserBalanceById(idWinner)) + bid.sum;
      const newBalanceLoser =
        (await this.usersService.getUserBalanceById(idLoser)) - bid.sum;

      if (newBalanceLoser < 0) {
        throw new BadRequestException(
          'The loser does not have enough funds on his balance',
        );
      }

      // обновление балансов в бд
      await this.usersService.updateUserBalance(idWinner, {
        balance: newBalanceWin,
      });
      await this.usersService.updateUserBalance(idLoser, {
        balance: newBalanceLoser,
      });

      //в текущей ставке обновляю победителя
      await this.bidsModel.findByIdAndUpdate(
        calculateBidDto.id_bid,
        { id_winner: idWinner },
        {
          new: true,
        },
      );

      //меняю статус пари на завершено
      await this.betsService.updateStatusByIdBet(bid.id_bet, true);
      return true;
    } catch (e) {
      throw new Error(e);
    }
  }
}
