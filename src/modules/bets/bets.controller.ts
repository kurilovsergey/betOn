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
import { BetsService } from './bets.service';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { JwtAuthGuard } from 'src/modules/auth/guards/jwt-auth.guard';
import { Bet } from './schemas/bet.schema';
import { CreateBetDto } from './dto/create-bet.dto';

@ApiTags('bets')
@Controller('bets')
export class BetsController {
  constructor(private readonly betsService: BetsService) {}

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Get()
  @ApiOperation({
    summary: 'Получить список всех пари',
  })
  getAllBets(): Promise<Bet[]> {
    return this.betsService.getAllBets();
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Get(':id')
  @ApiOperation({
    summary: 'Получить пари по ид',
  })
  getByIdBet(@Param('id') id: string): Promise<Bet> {
    return this.betsService.getByIdBet(id);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Get('users/:id_user')
  @ApiOperation({
    summary: 'Получение списка всех пари, созданных конкретным пользователем',
  })
  getBidsByIdUser(@Param('id_user') id_user: string): Promise<Bet[]> {
    return this.betsService.getBidsByIdUser(id_user);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Get('category/:id_category')
  @ApiOperation({
    summary: 'Получить список пари по ид категории',
  })
  getBetsByIdCategory(
    @Param('id_category') id_category: string,
  ): Promise<Bet[]> {
    return this.betsService.getBetsByIdCategory(id_category);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Post('create')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Создание нового пари',
  })
  createBet(@Body() createBetDto: CreateBetDto): Promise<Bet> {
    return this.betsService.createBet(createBetDto);
  }
}
