import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  Post,
  UseGuards,
} from '@nestjs/common';
import { BidsService } from './bids.service';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/modules/auth/guards/jwt-auth.guard';
import { Bid } from './schemas/bid.schema';
import { CreateBidDto } from './dto/create-bid.dto';
import { CalculateBidDto } from './dto/calculation-bid.dto';

@ApiTags('bids')
@Controller('bids')
export class BidsController {
  constructor(private readonly bidsService: BidsService) {}

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Get()
  @ApiOperation({
    summary: 'Получить список всех ставок',
  })
  getAllBids(): Promise<Bid[]> {
    return this.bidsService.getAllBids();
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Post('calculation')
  @ApiOperation({
    summary:
      'Меняет статус пари на завершенное, в зависимости от того, кто выиграл и рассчитывает, а именно отнимает сумму у одного юзера из кошелька и начисляет другому.',
  })
  calculationBid(@Body() calculateBidDto: CalculateBidDto): Promise<boolean> {
    return this.bidsService.calculationBid(calculateBidDto);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Post(':id_bet')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Сделать ставку на определенное пари',
  })
  createBid(
    @Body() createBidDto: CreateBidDto,
    @Param('id_bet') id_bet: string,
  ): Promise<Bid> {
    return this.bidsService.createBid(createBidDto, id_bet);
  }
}
