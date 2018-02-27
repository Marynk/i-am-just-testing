import { NgModule } from '@angular/core';
import { RouterModule, Routes } from '@angular/router';
import { TourOfHeroesComponent } from './tour-of-heroes/tour-of-heroes.component';
import { HeroesComponent} from "./tour-of-heroes/heroes/heroes.component";
import {DashboardComponent} from "./tour-of-heroes/dashboard/dashboard.component";
import { HeroDetailComponent} from "./tour-of-heroes/hero-detail/hero-detail.component"
import {JokesOfGodComponent} from "./jokes-of-god/jokes-of-god.component";

const routes: Routes = [
  { path: 'tour-of-heroes', component: TourOfHeroesComponent,
    children: [
      { path: '', redirectTo: 'dashboard', pathMatch: 'full' },
      { path: 'heroes', component: HeroesComponent,
      children: [
        { path: 'detail/:id', component: HeroDetailComponent }
      ]},
      { path: 'dashboard', component: DashboardComponent,
      children: [
        { path: 'detail/:id', component: HeroDetailComponent }
      ]},

    ]
  }, //
  {path: 'jokes-of-god', component: JokesOfGodComponent},
  {path: 'todo-list', component: TodoList}

];

@NgModule({
  exports: [ RouterModule ],
  imports: [ RouterModule.forRoot(routes) ],
})


export class AppRoutingModule {}
