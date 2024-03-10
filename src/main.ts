import { NestFactory } from '@nestjs/core';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';
import { AppModule } from './app.module';
import { AllExceptionsFilter } from './tools/exception-filters.filter';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.setGlobalPrefix('api');

  // add swagger
  const config = new DocumentBuilder()
    .setTitle('Api')
    .setDescription('The API for project')
    .setVersion('1.0')
    .addTag('API')
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('docs', app, document);

  app.useGlobalPipes(new ValidationPipe());

  //глобальный обработчик ошибок
  app.useGlobalFilters(new AllExceptionsFilter());

  app.enableCors();
  await app.listen(process.env.PORT || 3000);
}
bootstrap();
