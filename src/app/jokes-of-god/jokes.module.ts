import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';

import { JokeComponent } from './joke/joke.component';
import { JokeFormComponent } from './joke-form/joke-form.component';
import {JokesOfGodComponent} from "./jokes-of-god.component";


@NgModule({
  declarations: [
    JokesOfGodComponent,
    JokeComponent,
    JokeFormComponent
  ],
  imports: [
    BrowserModule,

  ],
  providers: [],
})
export class JokesModule { }
