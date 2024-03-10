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
import { EvidencesService } from './evidences.service';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { Evidence } from './schemas/evidence.schema';
import { CreateEvidenceDto } from './dto/create-evidence.dto';

@ApiTags('evidences')
@Controller('evidences')
export class EvidencesController {
  constructor(private readonly evidencesService: EvidencesService) {}

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Get(':id_bet')
  @ApiOperation({
    summary: 'Получение списка доказательств для определенного пари',
  })
  getEvidencesByIdBet(@Param('id_bet') id_bet: string): Promise<Evidence[]> {
    return this.evidencesService.getEvidencesByIdBet(id_bet);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Get(':id_bet/:id_user')
  @ApiOperation({
    summary:
      'Получение списка доказательств для определенного пари, предоставленных конкретным пользователем',
  })
  getEvidencesByIdBetAndIdUser(
    @Param('id_bet') id_bet: string,
    @Param('id_user') id_user: string,
  ): Promise<Evidence[]> {
    return this.evidencesService.getEvidencesByIdBetAndIdUser(id_bet, id_user);
  }

  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard)
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({
    summary: 'Создание нового доказательства для определенного пари',
  })
  createUser(@Body() createEvidenceDto: CreateEvidenceDto): Promise<Evidence> {
    return this.evidencesService.createEvidence(createEvidenceDto);
  }
}
