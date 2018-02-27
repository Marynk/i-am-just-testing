import { BrowserModule } from '@angular/platform-browser';
import { NgModule } from '@angular/core';
import { FormsModule } from '@angular/forms';

import { AppComponent } from './app.component';
import { TourOfHeroesComponent } from './tour-of-heroes/tour-of-heroes.component';
import { HeroesComponent } from './tour-of-heroes/heroes/heroes.component';

import { HeroService} from "./tour-of-heroes/hero.service";

import {AngularFireDatabaseModule } from "angularfire2/database";
import { AngularFireModule} from "angularfire2";
import { environment } from "../environments/environment";

import { AppRoutingModule } from './/app-routing.module';
import { HeroModule } from './tour-of-heroes/hero.module';
import { JokesModule } from './jokes-of-god/jokes.module';
import { TodoListComponent } from './todo-list/todo-list.component';

@NgModule({
  declarations: [
    AppComponent,
    TodoListComponent,
  ],
  imports: [
    BrowserModule,
    AngularFireModule.initializeApp(environment.firebase),
    AngularFireDatabaseModule,
    AppRoutingModule,
    HeroModule,
    JokesModule
  ],
  providers: [],
  bootstrap: [AppComponent]
})
export class AppModule { }
