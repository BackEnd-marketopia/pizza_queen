@extends('layouts.admin.app')

@section('title', translate('Menus'))

@section('content')
    <div class="content container-fluid">
        <div class="d-flex justify-content-between align-items-center mb-3">
            <h2 class="h1">{{ translate('Menus') }}</h2>
            <a href="{{ route('admin.menu.menu.create') }}" class="btn btn-primary">{{ translate('Add New Menu') }}</a>
        </div>

        <div class="card">
            <div class="card-body">
                <table class="table table-bordered">
                    <thead>
                        <tr>
                            <th>#</th>
                            <th>{{ translate('Image') }}</th>
                            <th>{{ translate('Action') }}</th>
                        </tr>
                    </thead>
                    <tbody>
                        @foreach ($menus as $key => $menu)
                            <tr>
                                <td>{{ $key + 1 }}</td>
                                <td><img src="{{ asset('storage/app/public/' . $menu->image) }}" width="50" alt="menu">
                                </td>
                                <td>
                                    <a href="{{ route('admin.menu.menu.edit', $menu->id) }}"
                                        class="btn btn-warning">{{ translate('Edit') }}</a>
                                    <form action="{{ route('admin.menu.menu.destroy', $menu->id) }}" method="POST"
                                        class="d-inline">
                                        @csrf
                                        @method('DELETE')
                                        <button type="submit" class="btn btn-danger">{{ translate('Delete') }}</button>
                                    </form>
                                </td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>
            <div class="card-footer">
                <div class="row justify-content-center justify-content-sm-between align-items-sm-center">
                    <div class="col-12">
                        {!! $menus->links() !!}
                    </div>
                </div>
            </div>
        </div>
    </div>
@endsection