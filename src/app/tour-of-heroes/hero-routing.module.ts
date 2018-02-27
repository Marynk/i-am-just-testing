import { NgModule } from '@angular/core';

import { RouterModule, Routes } from '@angular/router';
import {HeroesComponent} from './heroes/heroes.component';
import {HeroDetailComponent} from "./hero-detail/hero-detail.component";
//import { DashboardComponent } from './dashboard/dashboard.component';
//import { HeroDetailComponent } from './hero-detail/hero-detail.component';

const routes: Routes = [];

@NgModule({
  exports: [ RouterModule ],
  imports: [ RouterModule.forRoot(routes) ],
})


export class HeroRoutingModule {}
